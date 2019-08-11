// Package certs provides helpful methods for generating test certificates.
package certs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	rand2 "math/rand"
	"strconv"
	"testing"
	"time"
)

// Config can be provided to override the default values. The default values used are equivalent
// to a zero Config value (e.g. Config{}).
type Config struct {

	// CertPath specifies where to store the certificate. An empty string disables output. Files are PEM-encoded
	// for New and NewPEM and DER-encoded for NewDER.
	CertPath string

	// CertPath specifies where to store the key. An empty string disables output. Files are PEM-encoded
	// for New and NewPEM and DER-encoded for NewDER. Key files are unencrypted.
	KeyPath string

	// CACert specifies the CA certificate that signs the generated cert. Pass nil to create a self-signed
	// certificate.
	CACert *x509.Certificate

	// CAKey specifies the CA key that signs the generated cert. Pass nil to create a self-signed
	// certificate.
	CAKey crypto.Signer

	// DN is the distinguished name of the certificate. If nil, a DN is generated of the form 'CN=<random number>'.
	DN *pkix.Name

	// Expiry is the expiry time of the certificate. If zero, the expiry is set one year in the future.
	Expiry time.Time

	// SerialNumber specifies the certificate serial. If nil, a random SerialNumber is generated.
	SerialNumber *big.Int

	// KeyType indicates the type of key to generate.
	KeyType KeyType

	// KeySize indicates the size of the key to generate for RSA keys. If zero, RSA keys will be 2048 bits long.
	RSAKeySize int

	// Curve indicates the type of ECDSA key to generate. If nil, a P256 curve is used.
	Curve elliptic.Curve

	// IsCA indicates whether to set CA flags on the certificate.
	IsCA bool

	// Algorithm specifies the signature algorithm to use. If zero, SHA256WithRSA or ECDSAWithSHA256 is used
	// (according to the issuing key type).
	Algorithm x509.SignatureAlgorithm

	// nowTime is used by tests
	nowTime time.Time
}

// KeyType defines the type of key to generate.
type KeyType int

const (
	RSA KeyType = iota
	ECDSA
)

var maxSerial = big.NewInt(100000)

const (
	pemCertType = "CERTIFICATE"
	pemKeyType  = "PRIVATE KEY"

	coreKeyUsage = x509.KeyUsageDataEncipherment |
		x509.KeyUsageDigitalSignature |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageKeyAgreement

	caKeyUsage = coreKeyUsage | x509.KeyUsageCertSign
)

func genCertAndKey(cfg Config, pem bool) (*x509.Certificate, crypto.Signer, error) {

	err := validateConfig(cfg)
	if err != nil {
		return nil, nil, err
	}

	signingKeyType := cfg.KeyType
	selfSigned := true
	if cfg.CACert != nil && cfg.CAKey != nil {
		selfSigned = false

		switch cfg.CAKey.(type) {
		case *rsa.PrivateKey:
			signingKeyType = RSA
		case *ecdsa.PrivateKey:
			signingKeyType = RSA
		default:
			return nil, nil, errors.New("only RSA and ECDSA CA keys supported")
		}
	}

	var subjectKey crypto.Signer
	switch cfg.KeyType {
	case RSA:
		keySize := cfg.RSAKeySize
		if keySize == 0 {
			keySize = 2048
		}

		subjectKey, err = rsa.GenerateKey(rand.Reader, keySize)
	case ECDSA:
		curve := cfg.Curve
		if curve == nil {
			curve = elliptic.P256()
		}

		subjectKey, err = ecdsa.GenerateKey(curve, rand.Reader)
	}

	if err != nil {
		return nil, nil, wrapError(err, "failed to generate key")
	}

	serial := cfg.SerialNumber
	if serial == nil {
		serial, err = rand.Int(rand.Reader, maxSerial)
		if err != nil {
			return nil, nil, wrapError(err, "failed to generate serial")
		}
	}

	dn := cfg.DN
	if dn == nil {
		dn = &pkix.Name{CommonName: strconv.Itoa(rand2.Int())}
	}

	now := cfg.nowTime
	if now.IsZero() {
		now = time.Now()
	}

	expiry := cfg.Expiry
	if expiry.IsZero() {
		expiry = now.AddDate(1, 0, 0)
	}

	certUsage := coreKeyUsage
	if cfg.IsCA {
		certUsage = caKeyUsage
	}

	algorithm := cfg.Algorithm
	if algorithm == x509.UnknownSignatureAlgorithm {
		switch signingKeyType {
		case RSA:
			algorithm = x509.SHA256WithRSA
		case ECDSA:
			algorithm = x509.ECDSAWithSHA256
		}
	}

	template := &x509.Certificate{
		// Config settings
		SerialNumber: serial,
		Subject:      *dn,
		NotAfter:     expiry,
		IsCA:         cfg.IsCA,

		// Things we set ourselves
		NotBefore:             now,
		KeyUsage:              certUsage,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    algorithm,
	}

	var parent *x509.Certificate
	if selfSigned {
		parent = template
	} else {
		parent = cfg.CACert
	}

	issuerKey := cfg.CAKey
	if issuerKey == nil {
		issuerKey = subjectKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, subjectKey.Public(), issuerKey)
	if err != nil {
		return nil, nil, wrapError(err, "failed to generate certificate")
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, wrapError(err, "failed to generate certificate")
	}

	if cfg.CertPath != "" {
		var outBytes []byte
		if pem {
			outBytes, err = pemEncodeCert(certBytes)
			if err != nil {
				return nil, nil, wrapError(err, "failed to encode certificate")
			}
		} else {
			outBytes = certBytes
		}

		err = ioutil.WriteFile(cfg.CertPath, outBytes, 0644)
		if err != nil {
			return nil, nil, wrapError(err, "failed to write certificate")
		}
	}
	if cfg.KeyPath != "" {
		var keyBytes []byte

		switch cfg.KeyType {
		case RSA:
			keyBytes, err = x509.MarshalPKCS8PrivateKey(subjectKey.(*rsa.PrivateKey))
			if err != nil {
				return nil, nil, wrapError(err, "failed to encode key")
			}
		case ECDSA:
			keyBytes, err = x509.MarshalECPrivateKey(subjectKey.(*ecdsa.PrivateKey))
			if err != nil {
				return nil, nil, wrapError(err, "failed to encode key")
			}
		}

		if pem {
			keyBytes, err = pemEncodeKey(keyBytes)
			if err != nil {
				return nil, nil, wrapError(err, "failed to encode certificate")
			}
		}

		err = ioutil.WriteFile(cfg.KeyPath, keyBytes, 0644)
		if err != nil {
			return nil, nil, wrapError(err, "failed to write key")
		}
	}

	return cert, subjectKey, nil
}

func getConfig(cfgs []Config) Config {
	if len(cfgs) > 0 {
		return cfgs[0]
	}
	return Config{}
}

// New generates a certificate and private key. To override default values, pass
// a Config value.
func New(cfg ...Config) (*x509.Certificate, crypto.Signer, error) {
	cert, key, err := genCertAndKey(getConfig(cfg), true)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

// TNew generates a certificate and private key. To override default values, pass
// a Config value. If an error occurs, t.Error is called.
func TNew(t *testing.T, cfg ...Config) (*x509.Certificate, crypto.Signer) {
	c, k, err := New(cfg...)
	if err != nil {
		t.Error(err)
	}
	return c, k
}

// NewDER generates a certificate and private key in DER format. To override default values, pass
// a Config value.
func NewDER(cfg ...Config) (certificate []byte, key []byte, err error) {
	cert, signerKey, err := genCertAndKey(getConfig(cfg), false)
	if err != nil {
		return nil, nil, err
	}

	certificate = cert.Raw

	switch k := signerKey.(type) {
	case *rsa.PrivateKey:
		key, err = x509.MarshalPKCS8PrivateKey(k)

	case *ecdsa.PrivateKey:
		key, err = x509.MarshalECPrivateKey(k)
	}

	if err != nil {
		return nil, nil, err
	}

	return
}

// TNewDER generates a certificate and private key in DER format. To override default values, pass
// a Config value. If an error occurs, t.Error is called.
func TNewDER(t *testing.T, cfg ...Config) (certificate []byte, key []byte) {
	c, k, err := NewDER(cfg...)
	if err != nil {
		t.Error(err)
	}
	return c, k
}

// NewPEM generates a certificate and private key in PEM format. To override default values, pass
// a Config value.
func NewPEM(cfg ...Config) (certificate []byte, key []byte, err error) {

	certBytes, keyBytes, err := NewDER(getConfig(cfg))
	if err != nil {
		return nil, nil, err
	}

	c, err := pemEncodeCert(certBytes)
	if err != nil {
		return nil, nil, err
	}

	k, err := pemEncodeKey(keyBytes)
	if err != nil {
		return nil, nil, err
	}

	return c, k, nil
}

// TNewPEM generates a certificate and private key in PEM format. To override default values, pass
// a Config value. If an error occurs, t.Error is called.
func TNewPEM(t *testing.T, cfg ...Config) (certificate []byte, key []byte) {
	c, k, err := NewPEM(cfg...)
	if err != nil {
		t.Error(err)
	}
	return c, k
}

func pemEncodeCert(certBytes []byte) ([]byte, error) {
	return pemEncode(certBytes, pemCertType)
}

func pemEncodeKey(keyBytes []byte) ([]byte, error) {
	return pemEncode(keyBytes, pemKeyType)
}

func pemEncode(obj []byte, pemType string) ([]byte, error) {
	block := &pem.Block{
		Type:  pemType,
		Bytes: obj,
	}

	b := new(bytes.Buffer)

	if err := pem.Encode(b, block); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func validateConfig(cfg Config) error {
	// We reject only the most grievous errors

	switch cfg.KeyType {
	case RSA, ECDSA:
		// this is fine
	default:
		return errors.New("bad KeyType in config")
	}

	if cfg.SerialNumber != nil && cfg.SerialNumber.Cmp(big.NewInt(1)) == -1 {
		return errors.New("SerialNumber must be positive")
	}

	if cfg.RSAKeySize < 0 {
		return errors.New("RSAKeySize must be positive (or zero)")
	}

	return nil
}

func wrapError(err error, msg string) error {
	return errors.New(fmt.Sprintf("%s: %s", msg, err))
}
