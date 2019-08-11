package testcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestValidateConfig(t *testing.T) {
	err := validateConfig(Config{KeyType: KeyType(42)})
	assert.Error(t, err)

	err = validateConfig(Config{RSAKeySize: -1})
	assert.Error(t, err)
}

func TestDefaults(t *testing.T) {
	now := time.Now()
	cert, key := TCert(t, Config{nowTime: now})

	require.IsType(t, &rsa.PrivateKey{}, key)
	assert.Equal(t, 2048, key.(*rsa.PrivateKey).Size()*8)
	assert.Equal(t, x509.SHA256WithRSA, cert.SignatureAlgorithm)
	assert.Equal(t, cert.Subject, cert.Issuer)
	assertUTCTimeEqual(t, now.AddDate(1, 0, 0), cert.NotAfter)
	assertUTCTimeEqual(t, now, cert.NotBefore)

	// Check subject is empty except for common name
	emptyName := pkix.Name{}
	subject := cert.Subject
	subject.CommonName = ""
	subject.Names = nil // this would contained parsed entries
	assert.Equal(t, emptyName, subject)

	// Check subject common name is a number
	assert.Regexp(t, `\d+`, cert.Subject.CommonName)

	assert.False(t, cert.IsCA)
	assert.Equal(t, coreKeyUsage, cert.KeyUsage)
	assert.True(t, cert.BasicConstraintsValid)
}

// assertUTCTimeEqual truncates expected to match UTCTime accuracy and then compares with actual.
func assertUTCTimeEqual(t *testing.T, expected, actual time.Time) {
	// RFC 5280 Section 4.1.2.5.1 requires dates are stored to the nearest second
	truncExpected := expected.Truncate(time.Second)
	assert.Truef(t, truncExpected.Equal(actual), "Expected %s, found %s", truncExpected, actual)
}

func TestStoreToFileDER(t *testing.T) {
	dir, err := ioutil.TempDir("", "testcert")
	require.NoError(t, err)
	defer func() {
		err := os.RemoveAll(dir)
		assert.NoError(t, err)
	}()

	certPath := path.Join(dir, "cert")
	keyPath := path.Join(dir, "key")

	cert, key := TCertDER(t, Config{KeyPath: keyPath, CertPath: certPath})

	certBytes, err := ioutil.ReadFile(certPath)
	require.NoError(t, err)

	keyBytes, err := ioutil.ReadFile(keyPath)
	require.NoError(t, err)

	assert.Equal(t, cert, certBytes)
	assert.Equal(t, key, keyBytes)
}

func TestStoreToFilePEM(t *testing.T) {
	dir, err := ioutil.TempDir("", "testcert")
	require.NoError(t, err)
	defer func() {
		err := os.RemoveAll(dir)
		assert.NoError(t, err)
	}()

	certPath := path.Join(dir, "cert")
	keyPath := path.Join(dir, "key")

	cert, key := TCert(t, Config{KeyPath: keyPath, CertPath: certPath})

	certBytes, err := ioutil.ReadFile(certPath)
	require.NoError(t, err)

	keyBytes, err := ioutil.ReadFile(keyPath)
	require.NoError(t, err)

	certDer := pemDecode(t, certBytes, pemCertType)
	assert.Equal(t, cert.Raw, certDer)

	keyDer := pemDecode(t, keyBytes, pemKeyType)
	assert.Equal(t, x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey)), keyDer)
}

func TestNotUsingDefault(t *testing.T) {
	caCert, caKey := TCert(t, Config{KeyType: ECDSA})

	now := time.Now()

	cfg := Config{
		CACert: caCert,
		CAKey:  caKey,
		DN: &pkix.Name{
			Country:            []string{"GB"},
			Organization:       []string{"org"},
			OrganizationalUnit: []string{"ou"},
			Locality:           []string{"local"},
			Province:           []string{"prov"},
			StreetAddress:      []string{"addr"},
			PostalCode:         []string{"postal"},
			SerialNumber:       "serial",
			CommonName:         "foo",
			Names:              nil,
			ExtraNames:         nil,
		},
		Expiry:       time.Now().AddDate(0, 2, 5),
		SerialNumber: big.NewInt(42),
		KeyType:      ECDSA,
		RSAKeySize:   0,
		Curve:        elliptic.P384(),
		IsCA:         true,
		Algorithm:    x509.ECDSAWithSHA384,
		nowTime:      now,
	}

	cert, key, err := Cert(cfg)
	require.NoError(t, err)

	// Test key
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	assert.True(t, ok, "bad key type")
	if ok {
		assert.Equal(t, elliptic.P384(), ecdsaKey.Curve)
	}

	// Test cert
	assert.Equal(t, caCert.Subject, cert.Issuer)

	subject := cert.Subject
	subject.Names = nil
	assert.Equal(t, *cfg.DN, subject)

	assertUTCTimeEqual(t, cfg.Expiry, cert.NotAfter)
	assertUTCTimeEqual(t, cfg.nowTime, cert.NotBefore)

	assert.Equal(t, cfg.SerialNumber, cert.SerialNumber)
	assert.Equal(t, cfg.Algorithm, cert.SignatureAlgorithm)
	assert.Equal(t, cfg.IsCA, cert.IsCA)
	assert.Equal(t, caKeyUsage, cert.KeyUsage)
}

func TestRSASigningCert(t *testing.T) {
	caCert, caKey := TCert(t)
	cert, _ := TCert(t, Config{CACert: caCert, CAKey: caKey})
	assert.Equal(t, x509.SHA256WithRSA, cert.SignatureAlgorithm)
}

func TestBadConfig(t *testing.T) {
	badConfig := Config{
		KeyType: KeyType(33),
	}

	_, _, err := Cert(badConfig)
	assert.Error(t, err)
}

func TestTCertPEM(t *testing.T) {
	c, k := TCertPEM(t)

	certDer := pemDecode(t, c, pemCertType)
	_, err := x509.ParseCertificate(certDer)
	assert.NoError(t, err)

	keyDer := pemDecode(t, k, pemKeyType)
	_, err = x509.ParsePKCS1PrivateKey(keyDer)
	assert.NoError(t, err)
}

func TestECDSAToFile(t *testing.T) {
	dir, err := ioutil.TempDir("", "testcert")
	require.NoError(t, err)
	defer func() {
		err := os.RemoveAll(dir)
		assert.NoError(t, err)
	}()

	certPath := path.Join(dir, "cert")
	keyPath := path.Join(dir, "key")

	c, k := TCert(t, Config{KeyType: ECDSA, CertPath: certPath, KeyPath: keyPath})

	keyBytes, err := ioutil.ReadFile(keyPath)
	certBytes, err := ioutil.ReadFile(certPath)

	keyDer := pemDecode(t, keyBytes, pemKeyType)
	certDer := pemDecode(t, certBytes, pemCertType)

	k2, err := x509.ParseECPrivateKey(keyDer)
	require.NoError(t, err)
	assert.Equal(t, k, k2)

	c2, err := x509.ParseCertificate(certDer)
	require.NoError(t, err)
	assert.Equal(t, c, c2)
}

func TestECDSAKeyDER(t *testing.T) {
	_, k := TCertDER(t, Config{KeyType: ECDSA})
	_, err := x509.ParseECPrivateKey(k)
	require.NoError(t, err)
}

func TestNegativeSerial(t *testing.T) {
	_, _, err := Cert(Config{SerialNumber: big.NewInt(-5)})
	assert.Error(t, err)
}

func TestWrapError(t *testing.T) {
	const msg = "error message"
	const commentary = "foo"
	assert.Equal(t, fmt.Sprintf("%s: %s", commentary, msg), wrapError(errors.New(msg), commentary).Error())
}

func pemDecode(t *testing.T, pemData []byte, expectedHeader string) []byte {
	block, remain := pem.Decode(pemData)
	require.Len(t, remain, 0)
	require.Equal(t, expectedHeader, block.Type)
	return block.Bytes
}
