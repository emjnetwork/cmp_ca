package cmp

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Edu171002/cmp_ca/ca"
)

const contentType = "application/pkixcmp"

// Handler handles CMP requests over HTTP (RFC 6712).
// POST /  — accepts DER-encoded PKIMessage, returns DER-encoded PKIMessage.
type Handler struct {
	CA *ca.CA
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "cannot read request body", http.StatusBadRequest)
		return
	}

	resp, err := h.handle(body)
	if err != nil {
		http.Error(w, fmt.Sprintf("cmp error: %v", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(resp)
}

// handle is the main dispatch function.
func (h *Handler) handle(data []byte) ([]byte, error) {
	var msg pkiMessage
	if _, err := asn1.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("unmarshal PKIMessage: %w", err)
	}

	switch msg.Body.Tag {
	case BodyIR:
		return h.handleCertReq(msg, BodyIP)
	case BodyKUR:
		return h.handleCertReq(msg, BodyKUP)
	default:
		return nil, fmt.Errorf("unsupported body type %d", msg.Body.Tag)
	}
}

// handleCertReq processes IR and KUR messages (both carry CertReqMessages).
func (h *Handler) handleCertReq(req pkiMessage, respBodyTag int) ([]byte, error) {
	// req.Body is [N] EXPLICIT { CertReqMessages }
	// req.Body.Bytes is the content inside the context tag, starting with
	// the SEQUENCE OF encoding of CertReqMessages.
	var rawMsgs []asn1.RawValue
	if _, err := asn1.Unmarshal(req.Body.Bytes, &rawMsgs); err != nil {
		return nil, fmt.Errorf("parse CertReqMessages: %w", err)
	}

	responses := make([]certResponse, 0, len(rawMsgs))
	for _, rawMsg := range rawMsgs {
		r, err := h.processCertReqMsg(rawMsg.Bytes)
		if err != nil {
			return nil, fmt.Errorf("process CertReqMsg: %w", err)
		}
		responses = append(responses, r)
	}

	return h.buildPKIMessage(req, respBodyTag, responses)
}

// processCertReqMsg parses a single CertReqMsg and issues the requested certificate.
// PoP (Proof of Possession) and RegInfo fields are intentionally ignored — this is
// a debug server.
func (h *Handler) processCertReqMsg(data []byte) (certResponse, error) {
	// CertReqMsg ::= SEQUENCE { CertRequest, [PoP OPTIONAL], [RegInfo OPTIONAL] }
	// Parse only the mandatory CertRequest (first element); ignore the rest.
	var req certRequest
	if _, err := asn1.Unmarshal(data, &req); err != nil {
		return certResponse{}, fmt.Errorf("parse CertRequest: %w", err)
	}

	tmpl, err := parseCertTemplate(req.CertTemplate.Bytes)
	if err != nil {
		return certResponse{}, fmt.Errorf("parse CertTemplate: %w", err)
	}

	cert, err := h.CA.IssueCert(tmpl)
	if err != nil {
		return certResponse{}, fmt.Errorf("issue certificate: %w", err)
	}

	ckp, err := buildCertifiedKeyPair(cert)
	if err != nil {
		return certResponse{}, fmt.Errorf("build CertifiedKeyPair: %w", err)
	}

	return certResponse{
		CertReqId:        req.CertReqId,
		Status:           pkiStatusInfo{Status: StatusGranted},
		CertifiedKeyPair: ckp,
	}, nil
}

// parseCertTemplate walks the context-tagged OPTIONAL fields of a CertTemplate
// (RFC 4211 section 5) and populates an *x509.Certificate template.
//
//	CertTemplate ::= SEQUENCE {
//	    version      [0] Version              OPTIONAL,
//	    serialNumber [1] INTEGER              OPTIONAL,
//	    signingAlg   [2] AlgorithmIdentifier  OPTIONAL,
//	    issuer       [3] Name                 OPTIONAL,
//	    validity     [4] OptionalValidity     OPTIONAL,
//	    subject      [5] Name                 OPTIONAL,
//	    publicKey    [6] SubjectPublicKeyInfo OPTIONAL,  -- REQUIRED by this server
//	    issuerUID    [7] UniqueIdentifier     OPTIONAL,
//	    subjectUID   [8] UniqueIdentifier     OPTIONAL,
//	    extensions   [9] Extensions          OPTIONAL
//	}
func parseCertTemplate(data []byte) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	rest := data
	for len(rest) > 0 {
		var field asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			return nil, fmt.Errorf("parse CertTemplate field: %w", err)
		}
		if field.Class != asn1.ClassContextSpecific {
			continue
		}

		switch field.Tag {
		case 5: // subject [5] Name (EXPLICIT → field.Bytes is the Name SEQUENCE)
			var rdns pkix.RDNSequence
			if _, err := asn1.Unmarshal(field.Bytes, &rdns); err != nil {
				return nil, fmt.Errorf("parse subject: %w", err)
			}
			tmpl.Subject.FillFromRDNSequence(&rdns)

		case 6: // publicKey [6] SubjectPublicKeyInfo
			pub, err := x509.ParsePKIXPublicKey(field.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse publicKey: %w", err)
			}
			tmpl.PublicKey = pub

		case 4: // validity [4] OptionalValidity
			notBefore, notAfter := parseOptionalValidity(field.Bytes)
			if !notBefore.IsZero() {
				tmpl.NotBefore = notBefore
			}
			if !notAfter.IsZero() {
				tmpl.NotAfter = notAfter
			}
		}
	}

	if tmpl.PublicKey == nil {
		return nil, errors.New("certTemplate is missing the required publicKey [6] field")
	}
	return tmpl, nil
}

// parseOptionalValidity extracts notBefore/notAfter from an OptionalValidity.
//
//	OptionalValidity ::= SEQUENCE {
//	    notBefore [0] Time OPTIONAL,
//	    notAfter  [1] Time OPTIONAL
//	}
//	Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
func parseOptionalValidity(data []byte) (notBefore, notAfter time.Time) {
	rest := data
	for len(rest) > 0 {
		var field asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			break
		}
		if field.Class != asn1.ClassContextSpecific {
			continue
		}

		var t time.Time
		// The inner bytes contain either UTCTime or GeneralizedTime.
		if _, err := asn1.Unmarshal(field.Bytes, &t); err != nil {
			continue
		}
		switch field.Tag {
		case 0:
			notBefore = t
		case 1:
			notAfter = t
		}
	}
	return
}

// buildCertifiedKeyPair constructs a DER-encoded CertifiedKeyPair ASN.1 value.
//
//	CertifiedKeyPair ::= SEQUENCE { certOrEncCert CertOrEncCert }
//	CertOrEncCert    ::= CHOICE   { certificate [0] CMPCertificate, ... }
//
// We use the certificate [0] alternative (CMPCertificate = Certificate).
func buildCertifiedKeyPair(cert *x509.Certificate) (asn1.RawValue, error) {
	// Unwrap the full DER certificate to get the inner SEQUENCE bytes.
	var rawCert asn1.RawValue
	if _, err := asn1.Unmarshal(cert.Raw, &rawCert); err != nil {
		return asn1.RawValue{}, err
	}

	// Wrap as CertOrEncCert: certificate [0] IMPLICIT Certificate.
	certOrEncCert := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      rawCert.Bytes,
	}

	// Wrap in CertifiedKeyPair SEQUENCE.
	ckpDER, err := asn1.Marshal(struct {
		CertOrEncCert asn1.RawValue
	}{certOrEncCert})
	if err != nil {
		return asn1.RawValue{}, err
	}

	var ckp asn1.RawValue
	if _, err := asn1.Unmarshal(ckpDER, &ckp); err != nil {
		return asn1.RawValue{}, err
	}
	return ckp, nil
}

// buildPKIMessage constructs the DER-encoded response PKIMessage.
func (h *Handler) buildPKIMessage(req pkiMessage, bodyTag int, responses []certResponse) ([]byte, error) {
	// --- caPubs: [1] SEQUENCE OF CMPCertificate ---
	// Go's asn1 uses a RawValue's own Class/Tag for marshaling and ignores
	// struct-level `explicit` tags.  Pre-encode caPubs as [1] CONSTRUCTED so
	// the SEQUENCE OF CMPCertificate is wrapped with the correct context tag.
	var rawCACert asn1.RawValue
	if _, err := asn1.Unmarshal(h.CA.Certificate.Raw, &rawCACert); err != nil {
		return nil, err
	}
	caPubsSeqDER, err := asn1.Marshal([]asn1.RawValue{rawCACert})
	if err != nil {
		return nil, err
	}
	// caPubs = A1 { 30 { cert } }  (context [1] CONSTRUCTED wrapping SEQUENCE OF Certificate)
	caPubs := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        1,
		IsCompound: true,
		Bytes:      caPubsSeqDER, // full SEQUENCE DER: 30 xx { cert }
	}

	// --- CertRepMessage ---
	certRep := certRepMessage{
		CAPubs:   caPubs,
		Response: responses,
	}
	certRepDER, err := asn1.Marshal(certRep)
	if err != nil {
		return nil, fmt.Errorf("marshal CertRepMessage: %w", err)
	}

	// Wrap CertRepMessage in the PKIBody CHOICE context tag.
	// With EXPLICIT TAGS (CMP module default), ir/kur bodies are:
	//   [N] EXPLICIT { SEQUENCE { CertRepMessage content } }
	// so body.Bytes must be the full SEQUENCE DER of CertRepMessage.
	body := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        bodyTag,
		IsCompound: true,
		Bytes:      certRepDER,
	}

	// --- Sender GeneralName: directoryName [4] Name ---
	caSubjectDER, err := asn1.Marshal(h.CA.Certificate.Subject.ToRDNSequence())
	if err != nil {
		return nil, err
	}
	var rawCASubject asn1.RawValue
	if _, err := asn1.Unmarshal(caSubjectDER, &rawCASubject); err != nil {
		return nil, err
	}
	sender := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4, // directoryName
		IsCompound: true,
		Bytes:      rawCASubject.Bytes,
	}

	// --- SenderNonce (fresh random 16 bytes) ---
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonceDER, err := asn1.Marshal(nonceBytes)
	if err != nil {
		return nil, err
	}
	var senderNonce asn1.RawValue
	if _, err := asn1.Unmarshal(nonceDER, &senderNonce); err != nil {
		return nil, err
	}

	// --- Build response PKIMessage ---
	respMsg := pkiMessage{
		Header: pkiHeader{
			PVNO:          2, // cmp2000
			Sender:        sender,
			Recipient:     req.Header.Sender,
			TransactionID: req.Header.TransactionID,
			SenderNonce:   senderNonce,
			RecipNonce:    req.Header.SenderNonce,
		},
		Body: body,
	}

	respDER, err := asn1.Marshal(respMsg)
	if err != nil {
		return nil, fmt.Errorf("marshal response PKIMessage: %w", err)
	}
	return respDER, nil
}
