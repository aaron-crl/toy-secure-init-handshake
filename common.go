package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"time"
)

type initNode struct {
	ClientAddress     string
	ClientCertificate []byte
}

type serverChallenge struct {
	ClientAddress     string
	ClientCertificate []byte
	Challenge         []byte
}

type clientAck struct {
	Ack []byte
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

// client challenge for server
func generateServerChallenge(clientCert []byte, serverCert []byte, secretToken []byte) []byte {
	message := append(clientCert, serverCert...)
	return computeHmac256(message, secretToken)
}

func validateServerChallenge(challenge serverChallenge, serverCert []byte, secretToken []byte) bool {
	expectedChallenge := append(challenge.ClientCertificate, serverCert...)
	return validHmac256(expectedChallenge, challenge.Challenge, secretToken)
}

func generateClientAck(challenge serverChallenge, secretToken []byte) (a clientAck) {
	a.Ack = computeHmac256(challenge.Challenge, secretToken)
	return
}

func validateClientAck(ack clientAck, clientCert []byte, serverCert []byte, secretToken []byte) bool {
	expectedChallenge := generateServerChallenge(clientCert, serverCert, secretToken)
	return validHmac256(expectedChallenge, ack.Ack, secretToken)
}

func createTLSConf(url string, lifespan time.Duration) (serverTLSConf *tls.Config, err error) {
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
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	// create empheral CA certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	// pem encode it
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	// extract hostname from URL
	hostname := strings.SplitN(url, ":", 2)[0]

	// bulid service template
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2000),
		Subject: pkix.Name{
			Organization: []string{"Cockroach Labs"},
			Country:      []string{"US"},
		},
		DNSNames: []string{hostname},
		// TODO this should be updated to work on non-localhost addresses
		//IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
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

	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return nil, err
	}

	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(caPEM.Bytes())

	// TODO this should probably be populated better
	serverTLSConf = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		RootCAs:      certpool,
	}

	return
}
