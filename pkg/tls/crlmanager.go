package tls

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	neturl "net/url"
	"sync"
	"time"

	"github.com/traefik/traefik/v2/pkg/log"
)

var (
	errCertificateCRLRevoked = errors.New("certificate revoked by CRL")
	errCacheItemNotFound     = errors.New("cache item not found")
)

var oidExtensionAuthorityKeyID = asn1.ObjectIdentifier{2, 5, 29, 35}

type crlManager struct {
	cache     map[string]*crlCacheItem
	cacheLock sync.RWMutex

	localCRLs []*pkix.CertificateList
}

type crlCacheItem struct {
	crl *pkix.CertificateList
}

func (cm *crlManager) RevocationCheck(cert *x509.Certificate) (error, error) {
	// Consult local CRLs first
	softErr, hardErr := cm.checkLocal(cert)
	if softErr != nil || hardErr != nil {
		return softErr, hardErr
	}

	// Consult remote CRLs thereafter
	return cm.checkRemote(cert)
}

func (cm *crlManager) checkLocal(cert *x509.Certificate) (error, error) {
	issuer := certificateIssuer(cert)

crlLoop:
	for _, crl := range cm.localCRLs {
		// Skip if CRL issuer mismatches certificate issuer
		// TODO(leon): Fail-hard if issuer == nil?
		if issuer != nil {
			if err := issuer.CheckCRLSignature(crl); err != nil {
				log.WithoutContext().Debugf("skipping local CRL due to issuer signature mismatch: %v", err)
				continue crlLoop
			}
		}

		// If the 'X509v3 Authority Key Identifier' is set, use it to verify if CRL comes from the CA which issued cert
		var didCheckAuthorityKeyID bool
		if cert.AuthorityKeyId != nil {
			// Find raw authority key ID value
			// TODO: Is this really required or always prefixed with 48 22 128 20?
			var certAuthorityKeyID []byte
			for _, e := range cert.Extensions {
				if e.Id.Equal(oidExtensionAuthorityKeyID) {
					certAuthorityKeyID = e.Value
					break
				}
			}
			for _, e := range crl.TBSCertList.Extensions {
				if e.Id.Equal(oidExtensionAuthorityKeyID) {
					didCheckAuthorityKeyID = true
					if !bytes.Equal(certAuthorityKeyID, e.Value) {
						log.WithoutContext().Debugf("skipping local CRL due to issuer authority key ID mismatch: %q != %q", certAuthorityKeyID, e.Value)
						continue crlLoop
					}
					break
				}
			}
		}

		if !didCheckAuthorityKeyID {
			// Fall back to silly issuer check
			if crl.TBSCertList.Issuer.String() != cert.Issuer.ToRDNSequence().String() {
				log.WithoutContext().Debugf("skipping local CRL due to issuer mismatch: %q != %q", crl.TBSCertList.Issuer.String(), cert.Issuer.ToRDNSequence().String())
				continue crlLoop
			}
		}

		softErr, hardErr := cm.revocationCheckAgainstCRL(crl, cert)
		if softErr != nil || hardErr != nil {
			return softErr, hardErr
		}
	}

	return nil, nil
}

func (cm *crlManager) checkRemote(cert *x509.Certificate) (error, error) {
	for _, url := range cert.CRLDistributionPoints {
		// Skip unsupported URL protocols
		if isLDAPURL(url) {
			log.WithoutContext().Debugf("skipping LDAP CRL URL: %q", url)
			continue
		}

		softErr, hardErr := cm.revocationCheckAgainstURL(url, cert)
		if softErr != nil || hardErr != nil {
			return softErr, hardErr
		}
	}

	return nil, nil
}

func (cm *crlManager) revocationCheckAgainstCRL(crl *pkix.CertificateList, cert *x509.Certificate) (error, error) {
	// Validate CRL certificate issuer signature
	issuer := certificateIssuer(cert)
	if issuer != nil {
		if err := issuer.CheckCRLSignature(crl); err != nil {
			return nil, err
		}
	}

	for _, revoked := range crl.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
			return nil, errCertificateCRLRevoked
		}
	}

	return nil, nil
}

func (cm *crlManager) revocationCheckAgainstURL(url string, cert *x509.Certificate) (error, error) {
	crl, softErr, hardErr := cm.crlByURL(url)
	if softErr != nil || hardErr != nil {
		return softErr, hardErr
	}

	return cm.revocationCheckAgainstCRL(crl, cert)
}

func (cm *crlManager) crlByURL(url string) (*pkix.CertificateList, error, error) {
	key := url

	// Note: The (read,write) operation is non-atomic. This might result in
	// duplicate fetches where the last value retrieved is actually stored.
	var haveItem bool
	var mustFetch bool
	item, err := cm.cacheItem(key)
	if err != nil {
		if !errors.Is(err, errCacheItemNotFound) {
			return nil, nil, err
		}
		// No such cache item yet
		mustFetch = true
	} else {
		haveItem = true
		mustFetch = item.crl.HasExpired(time.Now())
	}

	if mustFetch {
		crl, err := fetchCRL(url)
		// err = errors.New("revocationCheckStrict: true")
		if err != nil {
			// Only return error if we have no (stall) item
			if !haveItem {
				// This is a soft-fail
				return nil, err, nil
			}
			// Otherwise — currently — return stalled item
			// TODO(leon): Is this a good idea? Might want to make this configurable.
		} else {
			ni := &crlCacheItem{
				crl: crl,
			}
			// TODO(leon): We might not want to store the CRL before verifying its signature.
			cm.setCacheItem(key, ni)
			item = ni
			// Disabled due to golangcilint:ineffassign warning:
			// ineffectual assignment to `haveItem`
			// haveItem = true
		}
	}
	return item.crl, nil, nil
}

func (cm *crlManager) cacheItem(key string) (*crlCacheItem, error) {
	cm.cacheLock.RLock()
	defer cm.cacheLock.RUnlock()
	if e, ok := cm.cache[key]; ok {
		return e, nil
	}
	return nil, errCacheItemNotFound
}

func (cm *crlManager) setCacheItem(key string, item *crlCacheItem) {
	cm.cacheLock.Lock()
	cm.cache[key] = item
	cm.cacheLock.Unlock()
}

func newCRLManager(localCRLs []*pkix.CertificateList) *crlManager {
	return &crlManager{
		cache: make(map[string]*crlCacheItem),

		localCRLs: localCRLs,
	}
}

func isLDAPURL(url string) bool {
	u, err := neturl.Parse(url)
	if err != nil {
		return false
	}
	return u.Scheme == "ldap"
}

// TODO(leon): Add some kind of certificate cache?
// TODO(leon): This is completely untested yet.
func certificateIssuer(cert *x509.Certificate) (issuer *x509.Certificate) {
	var err error
	for _, issuingCert := range cert.IssuingCertificateURL {
		issuer, err = fetchCertificate(issuingCert)
		if err != nil {
			continue
		}
		break
	}
	return issuer
}

func fetchHTTP(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func fetchCertificate(url string) (*x509.Certificate, error) {
	cert, err := fetchHTTP(url)
	if err != nil {
		return nil, err
	}

	if block, _ := pem.Decode(cert); block != nil {
		cert = block.Bytes
	}

	return x509.ParseCertificate(cert)
}

func fetchCRL(url string) (*pkix.CertificateList, error) {
	crl, err := fetchHTTP(url)
	if err != nil {
		return nil, err
	}

	return x509.ParseCRL(crl)
}
