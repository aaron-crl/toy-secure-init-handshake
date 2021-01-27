package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

func runServer(selfAddress string, initCerts nodeInitTempCertificates, lifespan time.Duration, secretToken []byte, trustedPeers chan signedNodeHostnameAndCa) {

	// extract hostname from URL
	hostname := strings.SplitN(selfAddress, ":", 2)[0]

	serverCert, err := tls.X509KeyPair(initCerts.interNodeTempServiceCert, initCerts.interNodeTempServiceKey)
	if err != nil {
		log.Fatal("Failed to create server certificate key pair")
	}

	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(initCerts.interNodeTempCaCert)

	// TODO this should probably be populated better
	serviceTLSConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		RootCAs:      certpool,
	}

	trustServer := &http.Server{
		Addr:      selfAddress,
		Handler:   nil, // Default muxer
		TLSConfig: serviceTLSConf,
	}

	// initial endpoint for allow clients to grab server certificate
	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		fmt.Fprint(res, "Hello Custom World!")
	})

	http.HandleFunc("/trustInit", func(res http.ResponseWriter, req *http.Request) {
		challenge := signedNodeHostnameAndCa{}

		// TODO make this more error resilient to size and shape attacks
		err := json.NewDecoder(req.Body).Decode(&challenge)
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			log.Printf("/challenge: Bad Request from %s\n", req.RemoteAddr)
			return
		}

		log.Printf("Received challenge for client alleging to be: %s\n", challenge.Hostname)

		if !validSignedNodeHostnameAndCa(challenge, secretToken) {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}

		log.Printf("captured valid cert for %s\n", challenge.Hostname)

		// send the valid node infomation to the trustedPeers channel
		trustedPeers <- challenge

		// acknowledge validation to client
		ack := createSignedNodeHostnameAndCa(hostname, initCerts.interNodeTempCaCert, secretToken)
		json.NewEncoder(res).Encode(ack)
	})

	// start the server
	log.Fatal(trustServer.ListenAndServeTLS("", ""))
}

func main() {
	// CLI flags
	selfAddress := flag.String("selfAddress", "localhost:8443", "listening address for node")
	peerAddress := flag.String("peerAddress", "localhost:8443", "listening address for peer")
	lifespanRaw := flag.String("lifespanInSeconds", "600s", "number of seconds allowed for init period")
	secretToken := flag.String("initToken", "sUp3rSekret", "initialization passphrase")
	flag.Parse()

	lifespan, err := time.ParseDuration(*lifespanRaw)
	if nil != err {
		log.Fatal("Failed to parse lifespan duration")
	}

	selfHostname := strings.SplitN(*selfAddress, ":", 2)[0]

	tempCerts, err := createNodeInitTempCertificates(selfHostname, lifespan)
	if err != nil {
		log.Fatal("Failed to create certificates")
	}

	trustedPeers := make(chan signedNodeHostnameAndCa)

	go runClient(*peerAddress, selfHostname, tempCerts.interNodeTempCaCert, lifespan, []byte(*secretToken), trustedPeers)
	go runServer(*selfAddress, tempCerts, lifespan, []byte(*secretToken), trustedPeers)

	for p := range trustedPeers {
		// remember these are now PEM encoded
		caCert, _ := pem.Decode([]byte(p.CaCertificate))
		if nil == caCert {
			log.Fatal("Failed to parse valid PEM from CaCertificate blob")
		}
		cert, err := x509.ParseCertificate(caCert.Bytes)
		if nil != err {
			log.Fatal("Failed to parse valid Certificate from PEM blob")
		}
		fmt.Printf("Trusted cert for %s | Signature begins: %s...\n", p.Hostname, hex.EncodeToString(cert.Signature)[:12])
	}
}
