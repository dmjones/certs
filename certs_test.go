package testcert

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
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
	cert, key, err := Cert(Config{nowTime: now})
	require.NoError(t, err)

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

	cert, key, err := CertDER(Config{KeyPath: keyPath, CertPath: certPath})
	require.NoError(t, err)

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

	cert, key, err := Cert(Config{KeyPath: keyPath, CertPath: certPath})
	require.NoError(t, err)

	certBytes, err := ioutil.ReadFile(certPath)
	require.NoError(t, err)

	keyBytes, err := ioutil.ReadFile(keyPath)
	require.NoError(t, err)

	block, extra := pem.Decode(certBytes)
	assert.Len(t, extra, 0)
	assert.Equal(t, pemCertType, block.Type)
	assert.Equal(t, cert.Raw, block.Bytes)

	block, extra = pem.Decode(keyBytes)
	assert.Len(t, extra, 0)
	assert.Equal(t, pemKeyType, block.Type)
	assert.Equal(t, x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey)), block.Bytes)
}
