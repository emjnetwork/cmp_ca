// Package cmp provides a minimal CMP (Certificate Management Protocol, RFC 4210)
// server for testing and debugging Key Update Requests (KUR).
package cmp

import "encoding/asn1"

// PKIBody CHOICE tags (RFC 4210 appendix F, EXPLICIT TAGS module default).
const (
	BodyIR  = 0 // Initialization Request
	BodyIP  = 1 // Initialization Response
	BodyKUR = 7 // Key Update Request
	BodyKUP = 8 // Key Update Response
)

// PKIStatus values (RFC 4210 section 5.2.3).
const (
	StatusGranted   = 0
	StatusRejection = 2
)

// pkiMessage is the top-level CMP message (RFC 4210 section 5.1).
//
//	PKIMessage ::= SEQUENCE {
//	    header      PKIHeader,
//	    body        PKIBody,
//	    protection  [0] PKIProtection OPTIONAL,
//	    extraCerts  [1] SEQUENCE OF CMPCertificate OPTIONAL
//	}
type pkiMessage struct {
	Header     pkiHeader
	Body       asn1.RawValue
	Protection asn1.RawValue `asn1:"optional,explicit,tag:0"`
	ExtraCerts asn1.RawValue `asn1:"optional,explicit,tag:1"`
}

// pkiHeader is the CMP message header (RFC 4210 section 5.1.1).
// All optional fields use explicit context tags (EXPLICIT TAGS module default).
//
//	PKIHeader ::= SEQUENCE {
//	    pvno           INTEGER,
//	    sender         GeneralName,
//	    recipient      GeneralName,
//	    messageTime    [0] GeneralizedTime      OPTIONAL,
//	    protectionAlg  [1] AlgorithmIdentifier  OPTIONAL,
//	    senderKID      [2] KeyIdentifier        OPTIONAL,
//	    recipKID       [3] KeyIdentifier        OPTIONAL,
//	    transactionID  [4] OCTET STRING         OPTIONAL,
//	    senderNonce    [5] OCTET STRING         OPTIONAL,
//	    recipNonce     [6] OCTET STRING         OPTIONAL,
//	    freeText       [7] PKIFreeText          OPTIONAL,
//	    generalInfo    [8] SEQUENCE OF InfoTypeAndValue OPTIONAL
//	}
type pkiHeader struct {
	PVNO          int
	Sender        asn1.RawValue // GeneralName
	Recipient     asn1.RawValue // GeneralName
	MessageTime   asn1.RawValue `asn1:"optional,explicit,tag:0"`
	ProtectionAlg asn1.RawValue `asn1:"optional,explicit,tag:1"`
	SenderKID     asn1.RawValue `asn1:"optional,explicit,tag:2"`
	RecipKID      asn1.RawValue `asn1:"optional,explicit,tag:3"`
	TransactionID asn1.RawValue `asn1:"optional,explicit,tag:4"`
	SenderNonce   asn1.RawValue `asn1:"optional,explicit,tag:5"`
	RecipNonce    asn1.RawValue `asn1:"optional,explicit,tag:6"`
	FreeText      asn1.RawValue `asn1:"optional,explicit,tag:7"`
	GeneralInfo   asn1.RawValue `asn1:"optional,explicit,tag:8"`
}

// certRequest represents the CertRequest structure (RFC 4211 section 5).
//
//	CertRequest ::= SEQUENCE {
//	    certReqId    INTEGER,
//	    certTemplate CertTemplate,
//	    controls     Controls OPTIONAL
//	}
type certRequest struct {
	CertReqId    int
	CertTemplate asn1.RawValue
}

// certRepMessage is the certificate response (RFC 4210 section 5.3.4).
//
//	CertRepMessage ::= SEQUENCE {
//	    caPubs    [1] SEQUENCE OF CMPCertificate OPTIONAL,
//	    response      SEQUENCE OF CertResponse
//	}
//
// Note: for asn1.RawValue fields, Go's asn1 marshaller uses the RawValue's own
// Class/Tag directly and ignores struct-level `explicit`/`implicit` tags.
// CAPubs is therefore pre-encoded as [1] CONSTRUCTED in buildPKIMessage.
type certRepMessage struct {
	CAPubs   asn1.RawValue  `asn1:"optional"`
	Response []certResponse
}

// certResponse is one response per certificate request.
//
//	CertResponse ::= SEQUENCE {
//	    certReqId        INTEGER,
//	    status           PKIStatusInfo,
//	    certifiedKeyPair CertifiedKeyPair OPTIONAL,
//	    rspInfo          OCTET STRING     OPTIONAL
//	}
type certResponse struct {
	CertReqId        int
	Status           pkiStatusInfo
	CertifiedKeyPair asn1.RawValue `asn1:"optional"`
}

// pkiStatusInfo carries the result of a PKI operation.
//
//	PKIStatusInfo ::= SEQUENCE {
//	    status        PKIStatus,
//	    statusString  PKIFreeText    OPTIONAL,
//	    failInfo      PKIFailureInfo OPTIONAL
//	}
type pkiStatusInfo struct {
	Status int
}
