package cmp_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Edu171002/cmp_ca/ca"
	"github.com/Edu171002/cmp_ca/cmp"
)

// newTestHandler creates a Handler backed by a fresh CA for use in tests.
func newTestHandler(t *testing.T) *cmp.Handler {
	t.Helper()
	c, err := ca.New()
	if err != nil {
		t.Fatalf("ca.New() error: %v", err)
	}
	return &cmp.Handler{CA: c}
}

// buildIRMessage constructs a minimal DER-encoded PKIMessage containing an
// Initialization Request (IR) for the given public key and subject.
func buildIRMessage(t *testing.T, pub *rsa.PublicKey, subject pkix.Name) []byte {
	t.Helper()
	return buildCertReqMessage(t, pub, subject, cmp.BodyIR)
}

// buildKURMessage constructs a minimal DER-encoded PKIMessage containing a
// Key Update Request (KUR).
func buildKURMessage(t *testing.T, pub *rsa.PublicKey, subject pkix.Name) []byte {
	t.Helper()
	return buildCertReqMessage(t, pub, subject, cmp.BodyKUR)
}

// buildCertReqMessage is the shared builder for IR and KUR messages.
func buildCertReqMessage(t *testing.T, pub *rsa.PublicKey, subject pkix.Name, bodyTag int) []byte {
	t.Helper()

	// Encode the public key as SubjectPublicKeyInfo.
	spkiDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	// Build CertTemplate with subject [5] and publicKey [6].
	// RFC 4211 (CRMF) uses IMPLICIT TAGS: the context tag replaces the SEQUENCE tag,
	// so Bytes must contain only the inner content of the SEQUENCE (no outer tag+length).
	subjectDER, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		t.Fatalf("marshal subject: %v", err)
	}
	var nameRaw asn1.RawValue
	if _, err := asn1.Unmarshal(subjectDER, &nameRaw); err != nil {
		t.Fatalf("unmarshal Name: %v", err)
	}
	subjectField := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        5,
		IsCompound: true,
		Bytes:      nameRaw.Bytes, // inner content only (IMPLICIT: replaces SEQUENCE tag)
	}

	var spkiRaw asn1.RawValue
	if _, err := asn1.Unmarshal(spkiDER, &spkiRaw); err != nil {
		t.Fatalf("unmarshal SPKI: %v", err)
	}
	pubKeyField := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        6,
		IsCompound: true,
		Bytes:      spkiRaw.Bytes, // inner content only (IMPLICIT: replaces SEQUENCE tag)
	}

	certTemplateDER, err := asn1.Marshal(struct {
		Subject   asn1.RawValue
		PublicKey asn1.RawValue
	}{subjectField, pubKeyField})
	if err != nil {
		t.Fatalf("marshal CertTemplate: %v", err)
	}
	var rawCertTemplate asn1.RawValue
	asn1.Unmarshal(certTemplateDER, &rawCertTemplate)

	// Build CertRequest.
	certReqDER, err := asn1.Marshal(struct {
		CertReqId    int
		CertTemplate asn1.RawValue
	}{0, rawCertTemplate})
	if err != nil {
		t.Fatalf("marshal CertRequest: %v", err)
	}
	var rawCertReq asn1.RawValue
	asn1.Unmarshal(certReqDER, &rawCertReq)

	// CertReqMsg = SEQUENCE { CertRequest } (no PoP for this debug test).
	certReqMsgDER, err := asn1.Marshal(struct {
		CertReq asn1.RawValue
	}{rawCertReq})
	if err != nil {
		t.Fatalf("marshal CertReqMsg: %v", err)
	}
	var rawCertReqMsg asn1.RawValue
	asn1.Unmarshal(certReqMsgDER, &rawCertReqMsg)

	// CertReqMessages = SEQUENCE OF CertReqMsg.
	certReqMsgsDER, err := asn1.Marshal([]asn1.RawValue{rawCertReqMsg})
	if err != nil {
		t.Fatalf("marshal CertReqMessages: %v", err)
	}
	var rawCertReqMsgs asn1.RawValue
	asn1.Unmarshal(certReqMsgsDER, &rawCertReqMsgs)

	// Wrap in PKIBody CHOICE context tag.
	// With EXPLICIT TAGS, the body.Bytes must be the full CertReqMessages DER.
	body := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        bodyTag,
		IsCompound: true,
		Bytes:      certReqMsgsDER,
	}

	// Minimal PKIHeader: pvno + dummy sender + dummy recipient.

	//transactionID := make([]byte, 16)
	//rand.Read(transactionID)
	//tidDER, _ := asn1.Marshal(transactionID)
	//var rawTID asn1.RawValue
	//asn1.Unmarshal(tidDER, &rawTID)

	transactionID := make([]byte, 16)
	rand.Read(transactionID)

	senderNonce := make([]byte, 16)
	rand.Read(senderNonce)

	emptyDN := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      []byte{0x30, 0x00},
	}

	type headerType struct {
		PVNO          int
		Sender        asn1.RawValue `asn1:"omitempty"`
		Recipient     asn1.RawValue `asn1:"omitempty"`
		TransactionID []byte        `asn1:"optional,explicit,tag:4"`
		SenderNonce   []byte        `asn1:"optional,explicit,tag:5"`
	}

	header := headerType{
		PVNO:          2,
		Sender:        emptyDN,
		Recipient:     emptyDN,
		TransactionID: transactionID,
		SenderNonce:   senderNonce,
	}

	type msgType struct {
		Header headerType
		Body   asn1.RawValue
	}
	der, err := asn1.Marshal(msgType{Header: header, Body: body})
	if err != nil {
		t.Fatalf("marshal PKIMessage: %v", err)
	}
	return der
}

// extractCertFromResponse decodes the first issued certificate from a DER-encoded
// IP or KUP PKIMessage.
func extractCertFromResponse(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()

	type respHeader struct {
		PVNO          int
		Sender        asn1.RawValue
		Recipient     asn1.RawValue
		MessageTime   asn1.RawValue `asn1:"optional,explicit,tag:0"`
		ProtectionAlg asn1.RawValue `asn1:"optional,explicit,tag:1"`
		SenderKID     []byte        `asn1:"optional,explicit,tag:2"`
		RecipKID      []byte        `asn1:"optional,explicit,tag:3"`
		TransactionID []byte        `asn1:"optional,explicit,tag:4"`
		SenderNonce   []byte        `asn1:"optional,explicit,tag:5"`
		RecipNonce    []byte        `asn1:"optional,explicit,tag:6"`
	}
	type respMsg struct {
		Header respHeader
		Body   asn1.RawValue
	}
	var msg respMsg
	if _, err := asn1.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal response PKIMessage: %v", err)
	}

	// msg.Body.Bytes is the full CertRepMessage SEQUENCE DER (with EXPLICIT body tag).
	// Parse it as CertRepMessage.
	// CAPubs is pre-encoded as [1] CONSTRUCTED in the handler (RawValues carry their
	// own Class/Tag), so read it without an explicit-tag struct constraint.
	type certRepRaw struct {
		CAPubs   asn1.RawValue `asn1:"optional"`
		Response []asn1.RawValue
	}
	var certRep certRepRaw
	if _, err := asn1.Unmarshal(msg.Body.Bytes, &certRep); err != nil {
		t.Fatalf("unmarshal CertRepMessage: %v", err)
	}
	if len(certRep.Response) == 0 {
		t.Fatal("response contains no CertResponse entries")
	}

	// CertResponse ::= SEQUENCE { certReqId, status, certifiedKeyPair OPTIONAL }
	type statusRaw struct {
		Status int
	}
	type certRespRaw struct {
		CertReqId        int
		Status           statusRaw
		CertifiedKeyPair asn1.RawValue `asn1:"optional"`
	}
	var cr certRespRaw
	if _, err := asn1.Unmarshal(certRep.Response[0].FullBytes, &cr); err != nil {
		t.Fatalf("unmarshal CertResponse: %v", err)
	}
	if cr.Status.Status != cmp.StatusGranted {
		t.Fatalf("status = %d, want %d (granted)", cr.Status.Status, cmp.StatusGranted)
	}

	// CertifiedKeyPair ::= SEQUENCE { certOrEncCert CertOrEncCert }
	// CertOrEncCert   ::= CHOICE    { certificate [0] CMPCertificate }
	// The CertifiedKeyPair RawValue has Bytes = the inner SEQUENCE content.
	// That inner content starts with the CertOrEncCert, which is [0] CONSTRUCTED.
	var certOrEncCert asn1.RawValue
	if _, err := asn1.Unmarshal(cr.CertifiedKeyPair.Bytes, &certOrEncCert); err != nil {
		t.Fatalf("unmarshal CertOrEncCert: %v", err)
	}
	// certOrEncCert.Bytes is the inner Certificate SEQUENCE content.
	// Reconstruct the full Certificate DER by re-wrapping with SEQUENCE tag.
	fullCertDER, err := asn1.Marshal(asn1.RawValue{
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certOrEncCert.Bytes,
	})
	if err != nil {
		t.Fatalf("re-wrap certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(fullCertDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// ---------- tests ----------

func TestHandlerMethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestHandlerBadRequest(t *testing.T) {
	h := newTestHandler(t)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL, "application/pkixcmp", bytes.NewReader([]byte("not-asn1")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad-ASN1 status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestHandlerIR(t *testing.T) {
	h := newTestHandler(t)
	srv := httptest.NewServer(h)
	defer srv.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	reqDER := buildIRMessage(t, &key.PublicKey, pkix.Name{CommonName: "ir.example.com"})

	//Dump
	os.WriteFile("ir.der", reqDER, 0644)

	resp, err := http.Post(srv.URL, "application/pkixcmp", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("IR status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/pkixcmp" {
		t.Errorf("Content-Type = %q, want application/pkixcmp", ct)
	}

	var respDER bytes.Buffer
	respDER.ReadFrom(resp.Body)

	cert := extractCertFromResponse(t, respDER.Bytes())

	if cert.Subject.CommonName != "ir.example.com" {
		t.Errorf("issued CN = %q, want %q", cert.Subject.CommonName, "ir.example.com")
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: h.CA.CertPool()}); err != nil {
		t.Errorf("certificate verification failed: %v", err)
	}

	//Dump
	os.WriteFile("ip.der", respDER.Bytes(), 0644)
}

func TestHandlerKUR(t *testing.T) {
	h := newTestHandler(t)
	srv := httptest.NewServer(h)
	defer srv.Close()

	// First obtain an initial certificate via IR.
	origKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	irDER := buildIRMessage(t, &origKey.PublicKey, pkix.Name{CommonName: "kur.example.com"})
	resp1, _ := http.Post(srv.URL, "application/pkixcmp", bytes.NewReader(irDER))
	var irResp bytes.Buffer
	irResp.ReadFrom(resp1.Body)
	resp1.Body.Close()
	origCert := extractCertFromResponse(t, irResp.Bytes())

	// Now request a key update with a new key.
	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kurDER := buildKURMessage(t, &newKey.PublicKey, pkix.Name{CommonName: origCert.Subject.CommonName})

	resp2, err := http.Post(srv.URL, "application/pkixcmp", bytes.NewReader(kurDER))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("KUR status = %d, want 200", resp2.StatusCode)
	}

	var kurResp bytes.Buffer
	kurResp.ReadFrom(resp2.Body)
	renewedCert := extractCertFromResponse(t, kurResp.Bytes())

	if renewedCert.Subject.CommonName != "kur.example.com" {
		t.Errorf("renewed CN = %q, want %q", renewedCert.Subject.CommonName, "kur.example.com")
	}
	if renewedCert.SerialNumber.Cmp(origCert.SerialNumber) == 0 {
		t.Error("renewed cert has the same serial as the original")
	}
	if _, err := renewedCert.Verify(x509.VerifyOptions{Roots: h.CA.CertPool()}); err != nil {
		t.Errorf("renewed certificate verification failed: %v", err)
	}
}
