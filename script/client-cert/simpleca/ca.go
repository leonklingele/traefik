package simpleca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"time"
)

// https://shaneutt.com/blog/golang-ca-and-signed-cert-go/

// CA is a simple CA.
type CA struct {
	name string

	now      time.Time
	validity time.Time

	priv    *rsa.PrivateKey
	privPEM *bytes.Buffer
	cert    *x509.Certificate
	certPEM *bytes.Buffer
	crl     []byte

	clients        []*Client
	revokedClients []*Client

	rsaKeyLength int
}

// PrivPath returns the path to the CA's private key.
func (ca *CA) PrivPath() string {
	return ca.Brand(caPrivName)
}

// PrivBytes returns the bytes of the PEM-encoded private key.
func (ca *CA) PrivBytes() []byte {
	return ca.privPEM.Bytes()
}

// CertPath returns the path to the CA's cert.
func (ca *CA) CertPath() string {
	return ca.Brand(caCertName)
}

// CertBytes returns the bytes of the PEM-encoded cert.
func (ca *CA) CertBytes() []byte {
	return ca.certPEM.Bytes()
}

// CRLPath returns the path to the CA's CRL.
func (ca *CA) CRLPath() string {
	return ca.Brand(caCRLName)
}

// CRLBytes returns the bytes of the CRL.
func (ca *CA) CRLBytes() []byte {
	return ca.crl
}

func (ca *CA) init() error {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject: pkix.Name{
			Country:            []string{ca.Brand("Country")},
			Organization:       []string{ca.Brand("Organization")},
			OrganizationalUnit: []string{ca.Brand("OrganizationalUnit")},

			Locality: []string{ca.Brand("Locality")},
			Province: []string{ca.Brand("Province")},

			StreetAddress: []string{ca.Brand("StreetAddress")},
			PostalCode:    []string{ca.Brand("PostalCode")},

			SerialNumber: ca.Brand("SerialNumber"),
			CommonName:   ca.Brand("CommonName"),
		},
		NotBefore:             ca.now,
		NotAfter:              ca.validity,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	log.Print("generating CA private key… ")
	priv, err := rsa.GenerateKey(rand.Reader, ca.rsaKeyLength)
	if err != nil {
		return err
	}
	log.Println("done.")

	privPEM := new(bytes.Buffer)
	if err := pem.Encode(privPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}); err != nil {
		return err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certPEM := new(bytes.Buffer)
	if err := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		return err
	}

	// Re-parse cert so its Subject Key ID is set
	cert, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return err
	}

	ca.priv = priv
	ca.privPEM = privPEM
	ca.cert = cert
	ca.certPEM = certPEM

	return nil
}

// Brand brands strings for the CA.
func (ca *CA) Brand(n string) string {
	return ca.name + "-" + n
}

// NewClient creates a new client.
func (ca *CA) NewClient(name string, serial int64) (*Client, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			Country:            []string{name + " Country"},
			Organization:       []string{name + " Organization"},
			OrganizationalUnit: []string{name + " OrganizationalUnit"},

			Locality: []string{name + " Locality"},
			Province: []string{name + " Province"},

			StreetAddress: []string{name + " StreetAddress"},
			PostalCode:    []string{name + " PostalCode"},

			// SerialNumber: name + " SerialNumber",
			// CommonName:   name + " CommonName",
		},
		NotBefore:   ca.now,
		NotAfter:    ca.validity,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,

		CRLDistributionPoints: []string{fmt.Sprintf("http://localhost:%d/%s", httpPort, ca.CRLPath())},
	}

	log.Printf("generating %s's private key… ", name)
	priv, err := rsa.GenerateKey(rand.Reader, ca.rsaKeyLength)
	if err != nil {
		return nil, err
	}
	log.Println("done.")

	privPEM := new(bytes.Buffer)
	if err := pem.Encode(privPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}); err != nil {
		return nil, err
	}

	client := &Client{
		ca: ca,

		name: name,

		priv:    priv,
		privPEM: privPEM,
		cert:    cert,
	}
	if err := ca.signClient(client); err != nil {
		return nil, err
	}
	ca.clients = append(ca.clients, client)

	return client, nil
}

// Client returns the client at index num.
func (ca *CA) Client(num int) *Client {
	return ca.clients[num]
}

func (ca *CA) signClient(client *Client) error {
	signedBytes, err := x509.CreateCertificate(rand.Reader, client.cert, ca.cert, &client.priv.PublicKey, ca.priv)
	if err != nil {
		return err
	}

	signedPEM := new(bytes.Buffer)
	if err := pem.Encode(signedPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: signedBytes,
	}); err != nil {
		return err
	}

	client.signedPEM = signedPEM

	return nil
}

// RevokeClient revokes a client certificate.
func (ca *CA) RevokeClient(client *Client) error {
	ca.revokedClients = append(ca.revokedClients, client)

	var rev []pkix.RevokedCertificate
	for _, c := range ca.revokedClients {
		log.Println("revoking", c.name)
		rev = append(rev, pkix.RevokedCertificate{
			SerialNumber:   c.cert.SerialNumber,
			RevocationTime: ca.now.UTC(),
		})
	}

	crlBytes, err := ca.cert.CreateCRL(rand.Reader, ca.priv, rev, ca.now, ca.validity)
	if err != nil {
		return err
	}

	ca.crl = crlBytes

	return nil
}

// WriteFiles writes out all files.
// This includes certificates, private keys and a CRL.
func (ca *CA) WriteFiles() error {
	const (
		uRW    = 0600
		uRWgoR = 0644
	)

	if err := ioutil.WriteFile(ca.PrivPath(), ca.PrivBytes(), uRW); err != nil {
		return err
	}
	if err := ioutil.WriteFile(ca.CertPath(), ca.CertBytes(), uRWgoR); err != nil {
		return err
	}
	if err := ioutil.WriteFile(ca.CRLPath(), ca.CRLBytes(), uRWgoR); err != nil {
		return err
	}
	for _, c := range ca.clients {
		if err := ioutil.WriteFile(c.PrivPath(), c.PrivBytes(), uRW); err != nil {
			return err
		}
		if err := ioutil.WriteFile(c.CertPath(), c.CertBytes(), uRWgoR); err != nil {
			return err
		}
	}

	return nil
}

// NewCA creates a new CA.
func NewCA(name string) (*CA, error) {
	now := time.Now()
	ca := &CA{
		name: name,

		now:      now,
		validity: now.AddDate(10 /* years */, 0 /* months */, 0 /* days */),

		rsaKeyLength: 4096,
	}
	if err := ca.init(); err != nil {
		return nil, err
	}
	return ca, nil
}
