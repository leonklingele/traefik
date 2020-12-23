package tls

const certificateHeader = "-----BEGIN CERTIFICATE-----\n"

// +k8s:deepcopy-gen=true

// ClientAuth defines the parameters of the client authentication part of the TLS connection, if any.
type ClientAuth struct {
	CAFiles []FileOrContent `json:"caFiles,omitempty" toml:"caFiles,omitempty" yaml:"caFiles,omitempty"`
	// ClientAuthType defines the client authentication type to apply.
	// The available values are: "NoClientCert", "RequestClientCert", "VerifyClientCertIfGiven" and "RequireAndVerifyClientCert".
	ClientAuthType string `json:"clientAuthType,omitempty" toml:"clientAuthType,omitempty" yaml:"clientAuthType,omitempty" export:"true"`
	// CRLFiles lists paths to CRL files or the files' content directly.
	// It is used to do revocation checks based on the configured local CRLs.
	CRLFiles []FileOrContent `json:"crlFiles,omitempty" toml:"crlFiles,omitempty" yaml:"crlFiles,omitempty"`
	// RevocationCheckStrict defines whether to strictly validate a client certificate's revocation status (currently only CRL) in a fail-hard manner.
	// When set to true and client authentication is enforced, abort the handshake when any attempts to validate the client certificate's revocation status fail. Such a faillure might occur for instance when fetching one of the client certificate's CRL (when provided).
	RevocationCheckStrict bool `json:"revocationCheckStrict,omitempty" toml:"revocationCheckStrict,omitempty" yaml:"revocationCheckStrict,omitempty" export:"true"`
}

// +k8s:deepcopy-gen=true

// Options configures TLS for an entry point.
type Options struct {
	MinVersion               string     `json:"minVersion,omitempty" toml:"minVersion,omitempty" yaml:"minVersion,omitempty" export:"true"`
	MaxVersion               string     `json:"maxVersion,omitempty" toml:"maxVersion,omitempty" yaml:"maxVersion,omitempty" export:"true"`
	CipherSuites             []string   `json:"cipherSuites,omitempty" toml:"cipherSuites,omitempty" yaml:"cipherSuites,omitempty" export:"true"`
	CurvePreferences         []string   `json:"curvePreferences,omitempty" toml:"curvePreferences,omitempty" yaml:"curvePreferences,omitempty" export:"true"`
	ClientAuth               ClientAuth `json:"clientAuth,omitempty" toml:"clientAuth,omitempty" yaml:"clientAuth,omitempty"`
	SniStrict                bool       `json:"sniStrict,omitempty" toml:"sniStrict,omitempty" yaml:"sniStrict,omitempty" export:"true"`
	PreferServerCipherSuites bool       `json:"preferServerCipherSuites,omitempty" toml:"preferServerCipherSuites,omitempty" yaml:"preferServerCipherSuites,omitempty" export:"true"`
}

// +k8s:deepcopy-gen=true

// Store holds the options for a given Store.
type Store struct {
	DefaultCertificate *Certificate `json:"defaultCertificate,omitempty" toml:"defaultCertificate,omitempty" yaml:"defaultCertificate,omitempty" export:"true"`
}

// +k8s:deepcopy-gen=true

// CertAndStores allows mapping a TLS certificate to a list of entry points.
type CertAndStores struct {
	Certificate `yaml:",inline" export:"true"`
	Stores      []string `json:"stores,omitempty" toml:"stores,omitempty" yaml:"stores,omitempty" export:"true"`
}
