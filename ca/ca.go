// Package ca implements a simple Certificate Authority for CMP testing.
package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync/atomic"
	"time"
)

// CA holds the state of the Certificate Authority.
type CA struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	serialNum   int64
}

// New creates a new CA with a freshly generated RSA-4096 key and a self-signed
// root certificate valid for 10 years.
func New() (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "CMP Debug CA",
			Organization: []string{"CMP Debug"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return &CA{Certificate: cert, PrivateKey: key, serialNum: 1}, nil
}

// nextSerial atomically generates the next unique serial number.
func (ca *CA) nextSerial() *big.Int {
	n := atomic.AddInt64(&ca.serialNum, 1)
	return big.NewInt(n)
}

// IssueCert signs and returns a certificate for the given template.
// The caller must populate template.PublicKey before calling.
// If NotBefore / NotAfter are zero, defaults of −1 minute and +1 year are used.
func (ca *CA) IssueCert(template *x509.Certificate) (*x509.Certificate, error) {
	template.SerialNumber = ca.nextSerial()
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now().Add(-time.Minute)
	}
	if template.NotAfter.IsZero() {
		template.NotAfter = time.Now().Add(365 * 24 * time.Hour)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, template.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// RenewCert issues a replacement certificate for oldCert using newPub as the
// public key (pass nil to reuse the old key). The subject and SANs are copied
// from oldCert.
func (ca *CA) RenewCert(oldCert *x509.Certificate, newPub interface{}) (*x509.Certificate, error) {
	pub := oldCert.PublicKey
	if newPub != nil {
		pub = newPub
	}

	template := &x509.Certificate{
		Subject:        oldCert.Subject,
		DNSNames:       oldCert.DNSNames,
		IPAddresses:    oldCert.IPAddresses,
		EmailAddresses: oldCert.EmailAddresses,
		URIs:           oldCert.URIs,
		KeyUsage:       oldCert.KeyUsage,
		ExtKeyUsage:    oldCert.ExtKeyUsage,
		NotBefore:      time.Now().Add(-time.Minute),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		PublicKey:      pub,
	}
	return ca.IssueCert(template)
}

// CertPool returns an *x509.CertPool containing the CA certificate.
func (ca *CA) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate)
	return pool
}

// CertPEM returns the PEM-encoded CA certificate.
func (ca *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Certificate.Raw,
	})
}
