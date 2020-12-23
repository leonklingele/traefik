package v1alpha1

import (
	"github.com/traefik/traefik/v2/pkg/tls"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TLSOption is a specification for a TLSOption resource.
type TLSOption struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec TLSOptionSpec `json:"spec"`
}

// +k8s:deepcopy-gen=true

// TLSOptionSpec configures TLS for an entry point.
type TLSOptionSpec struct {
	MinVersion               string     `json:"minVersion,omitempty"`
	MaxVersion               string     `json:"maxVersion,omitempty"`
	CipherSuites             []string   `json:"cipherSuites,omitempty"`
	CurvePreferences         []string   `json:"curvePreferences,omitempty"`
	ClientAuth               ClientAuth `json:"clientAuth,omitempty"`
	SniStrict                bool       `json:"sniStrict,omitempty"`
	PreferServerCipherSuites bool       `json:"preferServerCipherSuites,omitempty"`
}

// +k8s:deepcopy-gen=true

// ClientAuth defines the parameters of the client authentication part of the TLS connection, if any.
type ClientAuth struct {
	// SecretName is the name of the referenced Kubernetes Secret to specify the
	// certificate details.
	SecretNames []string `json:"secretNames"`
	// ClientAuthType defines the client authentication type to apply.
	// The available values are: "NoClientCert", "RequestClientCert", "VerifyClientCertIfGiven" and "RequireAndVerifyClientCert".
	ClientAuthType string `json:"clientAuthType"`
	// CRLFiles lists paths to CRL files or the files' content directly.
	// It is used to do revocation checks based on the configured local CRLs.
	CRLFiles []tls.FileOrContent `json:"crlFiles"`
	// RevocationCheckStrict defines whether to strictly validate a client certificate's revocation status (currently only CRL) in a fail-hard manner.
	// When set to true and client authentication is enforced, abort the handshake when any attempts to validate the client certificate's revocation status fail. Such a faillure might occur for instance when fetching one of the client certificate's CRL (when provided).
	RevocationCheckStrict bool `json:"revocationCheckStrict"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TLSOptionList is a list of TLSOption resources.
type TLSOptionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []TLSOption `json:"items"`
}
