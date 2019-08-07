package testcert

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
	"math/big"
	rand2 "math/rand"
	"strconv"
	"time"
)

type Config struct {

	// CertPath specifies where to store the certificate. An empty string disables output.
	CertPath string

	// CertPath specifies where to store the key. An empty string disables output.
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
}

type KeyType int

const (
	RSA KeyType = iota
	ECDSA
)

var maxSerial = big.NewInt(100000)

func cert(cfg Config) ([]byte, crypto.Signer, error) {

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

	expiry := cfg.Expiry
	if expiry.IsZero() {
		expiry = time.Now().AddDate(1, 0, 0)
	}

	usage := x509.KeyUsageDataEncipherment |
		x509.KeyUsageDigitalSignature |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageKeyAgreement

	if cfg.IsCA {
		usage = usage | x509.KeyUsageCertSign
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
		NotBefore:             time.Now(),
		KeyUsage:              usage,
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

	return certBytes, subjectKey, nil
}

func Cert(cfg Config) (*x509.Certificate, crypto.Signer, error) {
	certBytes, key, err := cert(cfg)
	if err != nil {
		return nil, nil, err
	}

	c, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, wrapError(err, "failed to generate certificate")
	}

	return c, key, nil
}

func CertDER(cfg Config) (certificate []byte, key []byte, err error) {
	var signerKey crypto.Signer

	certificate, signerKey, err = cert(cfg)
	if err != nil {
		return nil, nil, err
	}

	switch k := signerKey.(type) {
	case *rsa.PrivateKey:
		key = x509.MarshalPKCS1PrivateKey(k)

	case *ecdsa.PrivateKey:
		key, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, nil, err
		}
	}

	return
}

func CertPEM(cfg Config) (certificate []byte, key []byte, err error) {
	certBytes, keyBytes, err := CertDER(cfg)
	if err != nil {
		return nil, nil, err
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}

	b := new(bytes.Buffer)

	if err = pem.Encode(b, block); err != nil {
		return nil, nil, err
	}

	certificate = b.Bytes()

	b.Reset()
	block.Type = "PRIVATE KEY"
	block.Bytes = keyBytes

	if err = pem.Encode(b, block); err != nil {
		return nil, nil, err
	}

	key = b.Bytes()
	return
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
