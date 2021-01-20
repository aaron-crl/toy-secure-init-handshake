package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

func runServer(selfAddress string, lifespan time.Duration, secretToken []byte, trustedPeers chan initNode) {

	serviceTLSConf, err := createTLSConf(selfAddress, lifespan)
	if nil != err {
		log.Fatal("Creating service TLS configuration failed")
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

	// endpoint for handling client challenges
	http.HandleFunc("/challenge", func(res http.ResponseWriter, req *http.Request) {

		challenge := serverChallenge{}

		// TODO make this more error resilient to size and shape attacks
		err := json.NewDecoder(req.Body).Decode(&challenge)
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			log.Printf("/challenge: Bad Request from %s\n", req.RemoteAddr)
			return
		}

		log.Printf("Received challenge for client alleging to be: %s\n", challenge.ClientAddress)

		//clientCert: I couldn't figure out how to do this with noverify so falling back on client HMAC assurances
		// TODO: if there's a way to get the client cert here then we should do that instead of trusting the request
		serverCert := serviceTLSConf.Certificates[0].Certificate[0]

		if !validateServerChallenge(challenge, serverCert, secretToken) {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}

		log.Printf("captured valid cert for %s\n", challenge.ClientAddress)

		// send the valid node infomation to the trustedPeers channel
		node := initNode{
			ClientAddress:     challenge.ClientAddress,
			ClientCertificate: challenge.ClientCertificate,
		}
		trustedPeers <- node

		// acknowledge validation to client
		ack := generateClientAck(challenge, secretToken)
		json.NewEncoder(res).Encode(ack)
	})

	// start the server
	log.Fatal(trustServer.ListenAndServeTLS("", ""))
}

func main() {
	// hardcoded for testing
	lifespan, err := time.ParseDuration("600s")
	if nil != err {
		log.Fatal("Failed to parse lifespan duration")
	}
	selfAddress := "localhost:8443"
	peerAddress := "localhost:8443"
	secretToken := []byte("secretFoo")

	trustedPeers := make(chan initNode)

	go runClient(peerAddress, selfAddress, lifespan, secretToken, trustedPeers)
	go runServer(selfAddress, lifespan, secretToken, trustedPeers)

	for p := range trustedPeers {
		cert, err := x509.ParseCertificate(p.ClientCertificate)
		if nil != err {
			log.Fatal("Wait what?")
		}
		fmt.Printf("Trusted cert for %s | Signature begins: %s...\n", p.ClientAddress, hex.EncodeToString(cert.Signature)[:12])
	}
}
