[![GoDoc](https://godoc.org/github.com/dmjones/certs?status.svg)](https://godoc.org/github.com/dmjones/certs)

Generate test certificates for Go programs.

## Basic Usage

Grab a copy of the package:

```
go get github.com/dmjones/certs
```

Simple certificates can be created using `Cert`, `CertDER` and `CertPEM`:

```go
cert, key, err := certs.New()           // returns *x509.Certificate and crypto.Signer
certDER, keyDER, err := certs.NewDER()  // returns DER-encoded
certPEM, keyPEM, err := certs.NewPEM()  // returns PEM-encoded
```

These certificate will have default properties, including:

- Self-signed (using SHA256WithRSA)
- RSA 2048-bit keys
- One year validity
- Random serial number
- Random Common Name (all other DN fields blank)

These properties can be overriden. See examples below, or 
the docs for the `Config` class for more details.

### Avoid the error check

In a testing environment, you can avoid checking for the error by using the
equivalent TNew, TNewDER and TNewPEM functions:

```go
func TestSomething(t *testing.T) {
    cert, key, err := certs.TNew(t)           // returns *x509.Certificate and crypto.Signer
    certDER, keyDER, err := certs.TNewDER(t)  // returns DER-encoded
    certPEM, keyPEM, err := certs.TNewPEM(t)  // returns PEM-encoded
}
```

### Save to file

If you need to save to file, pass a `Config` argument and provide either (or both) of `CertPath` and
`KeyPath`:

```go
cert, key, err := certs.New(certs.Config{CertPath: "/tmp/cert.cert", KeyPath: "/tmp/key.pem"})
```

### Override defaults

Pass a `Config` argument to override the default settings. You only need to specify the
elements you wish to override. Below is an example that overrides every supported setting:

```go
cfg := certs.Config{
    CACert: otherCert,
    CAKey:  otherKey,
    DN: &pkix.Name{
        Country:            []string{"GB"},
        Organization:       []string{"org"},
        OrganizationalUnit: []string{"ou"},
        CommonName:         "foo",
    },
    Expiry:       time.Now().AddDate(0, 2, 5),
    SerialNumber: big.NewInt(42),
    KeyType:      certs.ECDSA,
    RSAKeySize:   0,
    Curve:        elliptic.P384(),
    IsCA:         true,
    Algorithm:    x509.ECDSAWithSHA384,
}

cert, key, err := certs.New(cfg)
```