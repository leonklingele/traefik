package simpleca

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
)

// Client is a client as created by a simple CA.
type Client struct {
	// Issuing CA
	ca *CA

	name string

	priv    *rsa.PrivateKey
	privPEM *bytes.Buffer
	cert    *x509.Certificate

	signedPEM *bytes.Buffer
}

// PrivPath returns the path to the client's private key.
func (c *Client) PrivPath() string {
	return c.ca.Brand(c.name + extPriv)
}

// PrivBytes returns the bytes of the PEM-encoded private key.
func (c *Client) PrivBytes() []byte {
	return c.privPEM.Bytes()
}

// CertPath returns the path to the client's cert.
func (c *Client) CertPath() string {
	return c.ca.Brand(c.name + extCert)
}

// CertBytes returns the bytes of the PEM-encoded cert.
func (c *Client) CertBytes() []byte {
	return c.signedPEM.Bytes()
}
