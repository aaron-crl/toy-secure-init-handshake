package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"log"
	"math/big"
	"time"
)

// PEM encoded versions of certificates for node
type nodeInitTempCertificates struct {
	interNodeTempCaCert      []byte
	interNodeTempCaKey       []byte
	interNodeTempServiceCert []byte
	interNodeTempServiceKey  []byte
}

// Blob used for symetric exchange of node public CA keys
type signedNodeHostnameAndCa struct {
	HostAddress   string
	Hostname      string
	CaCertificate []byte
	HMAC          []byte
}

// internode trust delivery struct
type nodeTrustBundle struct {
	CaCertPEM []byte
	CaKeyPEM  []byte
	HMAC      []byte
}

// helper function for hmac because go makes it
// easy to screw this up
func computeHmac256(message []byte, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return h.Sum(nil)
}

// helper function for hmac verification
func validHmac256(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

// Symetric server/client CA blob signature
func createSignedNodeHostnameAndCa(hostname string, caCert []byte, secretToken []byte) (signedMessage signedNodeHostnameAndCa) {
	signedMessage = signedNodeHostnameAndCa{}
	signedMessage.Hostname = hostname
	signedMessage.CaCertificate = caCert

	message := append([]byte(hostname), caCert...)
	signedMessage.HMAC = computeHmac256(message, secretToken)

	return
}

// Symetric validation function
func validSignedNodeHostnameAndCa(signedMessage signedNodeHostnameAndCa, secretToken []byte) bool {
	message := append([]byte(signedMessage.Hostname), signedMessage.CaCertificate...)
	return validHmac256(message, signedMessage.HMAC, secretToken)
}

// trust bundle builder
func createTrustBundle(lifespan time.Duration, secretToken []byte) (bundle nodeTrustBundle) {
	// This function creates a short lived initial CA for node initialization

	notBefore := time.Now()
	notAfter := time.Now().Add(lifespan)

	// create random serial number for CA
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))
	serialNumber, err := rand.Int(rand.Reader, max)
	if nil != err {
		log.Fatal("Failed to create random serial number")
	}

	// Create short lived initial CA template
	ca := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Cockroach Labs"},
			Country:      []string{"US"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	// create CA certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return
	}

	// pem encode it
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	bundle.CaCertPEM = caPEM.Bytes()
	bundle.CaKeyPEM = caPrivKeyPEM.Bytes()

	// MAC of cert and key concatinated
	message := append(bundle.CaCertPEM, bundle.CaKeyPEM...)
	bundle.HMAC = computeHmac256(message, secretToken)

	return
}

// trust bundle verifier
func validTrustBundle(bundle nodeTrustBundle, secretToken []byte) bool {
	message := append(bundle.CaCertPEM, bundle.CaKeyPEM...)
	return validHmac256(message, bundle.HMAC, secretToken)
}

// helper function to extract signatures
func pemToSignature(caCertPEM []byte) (signature string, err error) {

	caCert, _ := pem.Decode([]byte(caCertPEM))
	if nil == caCert {
		log.Println("Failed to parse valid PEM from CaCertificate blob")
		return
	}

	cert, err := x509.ParseCertificate(caCert.Bytes)
	if nil != err {
		log.Println("Failed to parse valid Certificate from PEM blob")
		return
	}

	signature = hex.EncodeToString(cert.Signature)

	return
}

func createNodeInitTempCertificates(hostname string, lifespan time.Duration) (certs nodeInitTempCertificates, err error) {
	// Establish usage window
	notBefore := time.Now()
	notAfter := time.Now().Add(lifespan)

	// Create ephemeral CA template
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1000),
		Subject: pkix.Name{
			Organization: []string{"Cockroach Labs"},
			Country:      []string{"US"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		IsCA:      true,
		//ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	// create empheral CA certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return
	}

	// pem encode it
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	// bulid service template
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2000),
		Subject: pkix.Name{
			Organization: []string{"Cockroach Labs"},
			Country:      []string{"US"},
		},
		DNSNames:    []string{hostname},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	certs.interNodeTempCaCert = caPEM.Bytes()
	certs.interNodeTempCaKey = caPrivKeyPEM.Bytes()
	certs.interNodeTempServiceCert = certPEM.Bytes()
	certs.interNodeTempServiceKey = certPrivKeyPEM.Bytes()

	return
}
