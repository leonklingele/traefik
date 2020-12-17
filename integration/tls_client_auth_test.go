package integration

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/go-check/check"
	"github.com/traefik/traefik/v2/integration/try"
	"github.com/traefik/traefik/v2/script/client-cert/simpleca"
	checker "github.com/vdemeester/shakers"
)

const (
	serverCertPath = "./fixtures/tlsclientauth/server/server.pem"
	serverKeyPath  = "./fixtures/tlsclientauth/server/server.key"

	ca1ID = 0
	ca2ID = 1
)

const (
	requestTimeout = 2 * time.Second
)

var errBadCertificateStr = "bad certificate"

type TLSClientAuthSuite struct {
	BaseSuite

	cas []*simpleca.CA
}

func (s *TLSClientAuthSuite) SetUpSuite(c *check.C) {
	s.createComposeProject(c, "tlsclientauth")
	s.composeProject.Start(c)

	const writeFiles = false
	cas, err := simpleca.BasicRun(writeFiles)
	c.Assert(err, checker.IsNil)
	s.cas = cas

	for _, ca := range cas {
		ca.RegisterHTTPHandlers()
	}
}

func (s *TLSClientAuthSuite) startCRLServer() func() error {
	// TODO: Should not wait for server to become available
	defer time.Sleep(2 * time.Second)
	return simpleca.ServeHTTP()
}

func (s *TLSClientAuthSuite) testrun(c *check.C, cfp string) (*http.Request, *http.Transport, *http.Transport, func()) {
	return s.testrunWithCRLID(c, cfp, -1)
}

func (s *TLSClientAuthSuite) testrunWithCRLID(c *check.C, cfp string, caIDForCRL int) (*http.Request, *http.Transport, *http.Transport, func()) {
	var cleanupFuncs []func() error
	cleanupFunc := func() {
		for _, cf := range cleanupFuncs {
			err := cf()
			c.Assert(err, checker.IsNil)
		}
	}

	ca1 := s.cas[ca1ID]
	caRootCertContent := ca1.CertBytes()

	var caCRLContent []byte
	if caIDForCRL > -1 {
		caCRLContent = s.cas[caIDForCRL].CRLBytes()
	}
	// Must provide CRL as file as its binary content.
	caCRLFile, err := ioutil.TempFile("", "crl")
	c.Assert(err, check.IsNil)
	caCRLPath := caCRLFile.Name()
	_, err = caCRLFile.Write(caCRLContent)
	c.Assert(err, check.IsNil)
	err = caCRLFile.Close()
	c.Assert(err, check.IsNil)
	cleanupFuncs = append(cleanupFuncs, func() error {
		return os.Remove(caCRLPath)
	})

	client1KeyPair, err := tls.X509KeyPair(ca1.Client(0).CertBytes(), ca1.Client(0).PrivBytes())
	c.Assert(err, check.IsNil)
	client2KeyPair, err := tls.X509KeyPair(ca1.Client(1).CertBytes(), ca1.Client(1).PrivBytes())
	c.Assert(err, check.IsNil)

	serverCertContent, err := ioutil.ReadFile(serverCertPath)
	c.Assert(err, check.IsNil)
	serverKeyContent, err := ioutil.ReadFile(serverKeyPath)
	c.Assert(err, check.IsNil)

	file := s.adaptFile(c, cfp, struct {
		CARootCertContent string
		CACRLPath         string

		ServerCertContent string
		ServerKeyContent  string
	}{
		CARootCertContent: string(caRootCertContent),
		CACRLPath:         caCRLPath,

		ServerCertContent: string(serverCertContent),
		ServerKeyContent:  string(serverKeyContent),
	})
	cleanupFuncs = append(cleanupFuncs, func() error {
		return os.Remove(file)
	})

	cmd, display := s.traefikCmd(withConfigFile(file))
	cleanupFuncs = append(cleanupFuncs, func() error {
		display(c)
		return nil
	})
	err = cmd.Start()
	c.Assert(err, checker.IsNil)
	cleanupFuncs = append(cleanupFuncs, func() error {
		s.killCmd(cmd)
		return nil
	})
	// TODO: Why do we need to wait for the server to spin up?
	time.Sleep(2 * time.Second)

	trClient1 := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{client1KeyPair},
		},
	}
	trClient2 := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{client2KeyPair},
		},
	}

	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:8443", nil)
	c.Assert(err, checker.IsNil)

	return req, trClient1, trClient2, cleanupFunc
}

func (s *TLSClientAuthSuite) requestShouldSucceed(c *check.C, req *http.Request, tr *http.Transport) {
	err := try.RequestWithTransport(req, requestTimeout, tr, try.StatusCodeIs(http.StatusOK))
	c.Assert(err, checker.IsNil)
}

func (s *TLSClientAuthSuite) requestShouldFail(c *check.C, req *http.Request, tr *http.Transport) {
	err := try.RequestWithTransport(req, requestTimeout, tr)
	c.Assert(err, checker.NotNil)
	c.Assert(err.Error(), checker.Contains, errBadCertificateStr)
}

func (s *TLSClientAuthSuite) TestTLSClientAuthCRL(c *check.C) {
	req, trClient1, trClient2, cleanupFunc := s.testrun(c, "./fixtures/tlsclientauth/crl.toml")
	defer cleanupFunc()

	// Request with client1 should succeed (soft-fail due to missing remote CRL)
	s.requestShouldSucceed(c, req, trClient1)
	// Request with client2 should succeed (soft-fail due to missing remote CRL)
	s.requestShouldSucceed(c, req, trClient2)

	// Boot up CRL server
	serverShutdownFunc := s.startCRLServer()

	// Request with client1 should succeed
	s.requestShouldSucceed(c, req, trClient1)
	// Request with client2 should fail
	s.requestShouldFail(c, req, trClient2)

	// Shut down CRL server
	c.Assert(serverShutdownFunc(), checker.IsNil)

	// Request with client1 should succeed (due to cached remote CRL)
	s.requestShouldSucceed(c, req, trClient1)
	// Request with client2 should fail (due to cached remote CRL)
	s.requestShouldFail(c, req, trClient2)
}

func (s *TLSClientAuthSuite) TestTLSClientAuthCRLStrict(c *check.C) {
	req, trClient1, trClient2, cleanupFunc := s.testrun(c, "./fixtures/tlsclientauth/crl_revocationCheckStrict.toml")
	defer cleanupFunc()

	// Request with client1 should fail (hard-fail due to missing remote CRL)
	s.requestShouldFail(c, req, trClient1)
	// Request with client2 should fail (hard-fail due to missing remote CRL)
	s.requestShouldFail(c, req, trClient2)

	// Boot up CRL server
	serverShutdownFunc := s.startCRLServer()

	// Request with client1 should succeed
	s.requestShouldSucceed(c, req, trClient1)
	// Request with client2 should fail
	s.requestShouldFail(c, req, trClient2)

	// Shut down CRL server
	c.Assert(serverShutdownFunc(), checker.IsNil)

	// Request with client1 should succeed (due to cached remote CRL)
	s.requestShouldSucceed(c, req, trClient1)
	// Request with client2 should fail (due to cached remote CRL)
	s.requestShouldFail(c, req, trClient2)
}

func (s *TLSClientAuthSuite) TestTLSClientAuthCRLWithCRLFiles(c *check.C) {
	req, trClient1, trClient2, cleanupFunc := s.testrunWithCRLID(c, "./fixtures/tlsclientauth/crl_crlFiles.toml", ca1ID)
	defer cleanupFunc()

	// Request with client1 should succeed (soft-fail due to being unrevoked in local CRL and missing remote CRL)
	s.requestShouldSucceed(c, req, trClient1)
	// Request with client2 should fail (due to local CRL)
	s.requestShouldFail(c, req, trClient2)
}

func (s *TLSClientAuthSuite) TestTLSClientAuthCRLWithCRLFilesDifferentCA(c *check.C) {
	req, trClient1, trClient2, cleanupFunc := s.testrunWithCRLID(c, "./fixtures/tlsclientauth/crl_crlFiles.toml", ca2ID)
	defer cleanupFunc()

	// Request with client1 should succeed (soft-fail due to being unrevoked in local CRL and missing remote CRL)
	s.requestShouldSucceed(c, req, trClient1)
	// Request with client2 should succeed (soft-fail due to being unrevoked in local CRL and missing remote CRL)
	s.requestShouldSucceed(c, req, trClient2)
}
