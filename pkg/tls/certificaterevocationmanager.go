package tls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"time"
)

type certificateRevocationManager struct {
	crlManager *crlManager
}

// Verify returns two errors. The first one being a soft-fail, the second one being a hard-fail error.
// A hard-fail error occurs when the certificate was revoked.
// A soft-fail error occurs when e.g. the certificate's CRL couldn't be fetched.
func (crm *certificateRevocationManager) Verify(cert *x509.Certificate) (error, error) {
	if err := crm.validateBeforeAfter(cert); err != nil {
		return nil, err
	}

	return crm.validateRevocation(cert)
}

func (crm *certificateRevocationManager) validateBeforeAfter(cert *x509.Certificate) error {
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return errors.New("certificate not yet valid")
	}
	if now.After(cert.NotAfter) {
		return errors.New("certificate expired")
	}
	return nil
}

func (crm *certificateRevocationManager) validateRevocation(cert *x509.Certificate) (error, error) {
	// Add other checks (e.g. OCSP) here.
	return crm.crlManager.RevocationCheck(cert)
}

func newCertificateRevocationManager(localCRLs []*pkix.CertificateList) *certificateRevocationManager {
	return &certificateRevocationManager{
		crlManager: newCRLManager(localCRLs),
	}
}
