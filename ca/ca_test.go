package ca_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/Edu171002/cmp_ca/ca"
)

func TestNew(t *testing.T) {
	c, err := ca.New()
	if err != nil {
		t.Fatalf("ca.New() error: %v", err)
	}
	if c.Certificate == nil {
		t.Fatal("Certificate is nil")
	}
	if !c.Certificate.IsCA {
		t.Error("Certificate.IsCA is false")
	}
}

func TestIssueCert(t *testing.T) {
	c, err := ca.New()
	if err != nil {
		t.Fatalf("ca.New() error: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey error: %v", err)
	}

	tmpl := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "test.example.com"},
		PublicKey: &key.PublicKey,
	}

	cert, err := c.IssueCert(tmpl)
	if err != nil {
		t.Fatalf("IssueCert error: %v", err)
	}

	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "test.example.com")
	}

	if _, err := cert.Verify(x509.VerifyOptions{Roots: c.CertPool()}); err != nil {
		t.Errorf("certificate verification failed: %v", err)
	}
}

func TestIssueCertIncreasesSerial(t *testing.T) {
	c, err := ca.New()
	if err != nil {
		t.Fatalf("ca.New() error: %v", err)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := func() *x509.Certificate {
		return &x509.Certificate{
			Subject:   pkix.Name{CommonName: "serial.example.com"},
			PublicKey: &key.PublicKey,
		}
	}

	cert1, _ := c.IssueCert(tmpl())
	cert2, _ := c.IssueCert(tmpl())

	if cert1.SerialNumber.Cmp(cert2.SerialNumber) == 0 {
		t.Error("two issued certificates have the same serial number")
	}
}

func TestRenewCert(t *testing.T) {
	c, err := ca.New()
	if err != nil {
		t.Fatalf("ca.New() error: %v", err)
	}

	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	orig, err := c.IssueCert(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "renew.example.com"},
		PublicKey: &key1.PublicKey,
	})
	if err != nil {
		t.Fatalf("IssueCert error: %v", err)
	}

	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	renewed, err := c.RenewCert(orig, &key2.PublicKey)
	if err != nil {
		t.Fatalf("RenewCert error: %v", err)
	}

	if renewed.Subject.CommonName != "renew.example.com" {
		t.Errorf("renewed CN = %q, want %q", renewed.Subject.CommonName, "renew.example.com")
	}
	if renewed.SerialNumber.Cmp(orig.SerialNumber) == 0 {
		t.Error("renewed cert has the same serial number as the original")
	}
	if _, err := renewed.Verify(x509.VerifyOptions{Roots: c.CertPool()}); err != nil {
		t.Errorf("renewed cert verification failed: %v", err)
	}
}

func TestRenewCertNilKey(t *testing.T) {
	c, err := ca.New()
	if err != nil {
		t.Fatalf("ca.New() error: %v", err)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	orig, _ := c.IssueCert(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "same-key.example.com"},
		PublicKey: &key.PublicKey,
	})

	// Pass nil to reuse the same public key.
	renewed, err := c.RenewCert(orig, nil)
	if err != nil {
		t.Fatalf("RenewCert(nil) error: %v", err)
	}
	if _, err := renewed.Verify(x509.VerifyOptions{Roots: c.CertPool()}); err != nil {
		t.Errorf("renewed cert verification failed: %v", err)
	}
}

func TestCertPEM(t *testing.T) {
	c, err := ca.New()
	if err != nil {
		t.Fatalf("ca.New() error: %v", err)
	}
	p := c.CertPEM()
	if len(p) == 0 {
		t.Fatal("CertPEM returned empty bytes")
	}
}
