package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

func getPeerCaCert(peerAddress string, selfHostname string, selfCaCert []byte, secretToken []byte) (peerCaCertAndHostname signedNodeHostnameAndCa, err error) {
	err = nil

	// TODO(aaron-crl): add TLS protocol level checks to make sure remote certificate matches profered one
	// This is non critical due to HMAC but would be good hygiene

	// connect to HTTPS endpoint unverified (effectively HTTP) with POST of challenge
	// HMAC(hostname + node CA public certificate, secretToken)
	clientTransport := http.DefaultTransport.(*http.Transport).Clone()
	clientTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{Transport: clientTransport}

	challenge := createSignedNodeHostnameAndCa(selfHostname, selfCaCert, secretToken)

	// Poll until valid or timeout
	body := new(bytes.Buffer)
	json.NewEncoder(body).Encode(challenge)
	res, err := client.Post("https://"+peerAddress+"/trustInit", "application/json; charset=utf-8", body)
	if nil != err {
		return
	}
	defer res.Body.Close()

	// read and validate server provided ack
	// HMAC(hostname + server CA public certificate, secretToken)
	serverAck := signedNodeHostnameAndCa{}
	json.NewDecoder(res.Body).Decode(&serverAck)

	// confirm response HMAC, if valid return peer bundle
	if !validSignedNodeHostnameAndCa(serverAck, secretToken) {
		log.Fatal("Failed to validate server response")
	}

	peerCaCertAndHostname = serverAck

	return
}

func runClient(peerHostname string, selfHostname string, selfCaCert []byte, lifespan time.Duration, secretToken []byte, trustedPeers chan signedNodeHostnameAndCa) {

	// retry for lifespan of certificates
	for start := time.Now(); time.Since(start) < lifespan; {
		peerHostnameAndCa, err := getPeerCaCert(peerHostname, selfHostname, selfCaCert, secretToken)
		if nil == err {
			trustedPeers <- peerHostnameAndCa
			log.Printf("Successfully established trust with peer: %s\n", peerHostnameAndCa.Hostname)
			return
		}

		// sleep for 1 second between attempts
		log.Printf("Error connected to peer (%s): %s", peerHostname, err)
		time.Sleep(time.Second)
	}

	log.Fatal("Lifespan of secret expired before node trust established.")
}
