package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strings"
	"time"
)

func runServer(selfAddress string, initCerts nodeInitTempCertificates, lifespan time.Duration, secretToken []byte, trustedPeers chan signedNodeHostnameAndCa, finishedInit chan bool) {

	// extract hostname from URL
	hostname := strings.SplitN(selfAddress, ":", 2)[0]

	serverCert, err := tls.X509KeyPair(initCerts.interNodeTempServiceCert, initCerts.interNodeTempServiceKey)
	if err != nil {
		log.Fatal("Failed to create server certificate key pair")
	}

	// setup trust service TLS listener config
	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(initCerts.interNodeTempCaCert)
	serviceTLSConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		RootCAs:      certpool,
	}

	trustServer := &http.Server{
		Addr:      selfAddress,
		Handler:   nil, // Default muxer
		TLSConfig: serviceTLSConf,
	}

	// handler for initial challenge and ack containing the ephemeral node CAs
	http.HandleFunc("/trustInit", func(res http.ResponseWriter, req *http.Request) {
		challenge := signedNodeHostnameAndCa{}

		// TODO (aaron-crl): [Security] make this more error resilient to size and shape attacks
		err := json.NewDecoder(req.Body).Decode(&challenge)
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			log.Printf("/challenge: Bad Request from %s\n", req.RemoteAddr)
			return
		}
		defer req.Body.Close()

		log.Printf("Received challenge for client alleging to be: %s\n", challenge.Hostname)

		if !validSignedNodeHostnameAndCa(challenge, secretToken) {
			http.Error(res, "invalid CA blob", http.StatusBadRequest)
			return
		}

		log.Printf("Captured valid cert for %s\n", challenge.HostAddress)

		// send the valid node infomation to the trustedPeers channel
		trustedPeers <- challenge

		// acknowledge validation to client
		ack := createSignedNodeHostnameAndCa(hostname, initCerts.interNodeTempCaCert, secretToken)
		ack.HostAddress = selfAddress
		json.NewEncoder(res).Encode(ack)

	})

	// endpoint to allow peer to deliver first internode CA trust material
	http.HandleFunc("/provisionTrust", func(res http.ResponseWriter, req *http.Request) {
		bundle := nodeTrustBundle{}

		err := json.NewDecoder(req.Body).Decode(&bundle)
		if err == nil {
			if validTrustBundle(bundle, secretToken) {
				// remember these are now PEM encoded
				sig, err := pemToSignature(bundle.CaCertPEM)
				if nil != err {
					log.Fatal("Failed to parse own CA signature?")
				}

				// successfully provisioned
				log.Printf("Recieved valid CA with signature %s\n", sig[:12])

				finishedInit <- true

			} else {
				log.Println("WARNING: Invalid CA bundle recieved, this may indicate unauthorized access.")
			}

			return
		}

		http.Error(res, err.Error(), http.StatusBadRequest)

		req.Body.Close()
		return
	})

	// start the server
	log.Fatal(trustServer.ListenAndServeTLS("", ""))
}

func sendSecret(peerAddress string, peerCaCertPEM []byte, caBundle nodeTrustBundle) (err error) {

	rootCAs, _ := x509.SystemCertPool()
	rootCAs.AppendCertsFromPEM(peerCaCertPEM)

	clientTransport := http.DefaultTransport.(*http.Transport).Clone()
	clientTransport.TLSClientConfig = &tls.Config{RootCAs: rootCAs}
	client := &http.Client{Transport: clientTransport}

	body := new(bytes.Buffer)
	json.NewEncoder(body).Encode(caBundle)
	res, err := client.Post("https://"+peerAddress+"/provisionTrust", "application/json; charset=utf-8", body)
	if nil != err {
		return
	}
	res.Body.Close()

	return
}

func main() {
	// CLI flags
	selfAddress := flag.String("selfAddress", "localhost:8443", "listening address for node")
	peerAddresses := flag.String("peerAddresses", "localhost:8443", "listening address for peer")
	lifespanRaw := flag.String("lifespan", "600s", "time allowed for init period")
	numNodes := flag.Int("numNodes", 3, "number of nodes being initialized")
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
	finishedInit := make(chan bool)

	// start server
	go runServer(*selfAddress, tempCerts, lifespan, []byte(*secretToken), trustedPeers, finishedInit)

	// start peer bind processes
	for _, peerAddress := range strings.Split(*peerAddresses, ",") {
		go runClient(peerAddress, *selfAddress, tempCerts.interNodeTempCaCert, lifespan, []byte(*secretToken), trustedPeers)
	}

	// wait until we have numNodes - 1 valid peers
	peerCaCerts := make(map[string]([]byte))
	for p := range trustedPeers {
		// remember these are now PEM encoded
		sig, err := pemToSignature(p.CaCertificate)
		if nil != err {
			log.Fatalf("Failed to parse valid cert for %s\n", p.HostAddress)
		}

		log.Printf("Trusted cert for %s | Signature begins: %s...\n", p.HostAddress, sig[:12])

		// Add or readd node to map
		peerCaCerts[p.HostAddress] = p.CaCertificate

		// check for enough peers
		if *numNodes-1 <= len(peerCaCerts) {
			break
		}
	}

	log.Println("Got enough peers!")

	// figure out if this node is lowest signature
	trustLeader := true
	selfSignature, _ := pemToSignature(tempCerts.interNodeTempCaCert)

	for _, peerCertPEM := range peerCaCerts {
		peerSignature, _ := pemToSignature(peerCertPEM)
		if selfSignature > peerSignature {
			trustLeader = false
		}
	}

	// if this is the lowest signature, do init, otherwise wait
	if trustLeader {
		log.Println("This node is trust leader. Building init bundle")
		// generate initial inter-node CA
		// TODO (aaron-crl): [Enhancement] replace lifespan reuse with separate flag
		trustBundle := createTrustBundle(lifespan, []byte(*secretToken))

		// log our CA fingerprint
		sig, err := pemToSignature(trustBundle.CaCertPEM)
		if nil != err {
			log.Fatal("Failed to parse own CA signature?")
		}
		log.Printf("Distributing trust CA with signature: %s", sig[:12])

		// for each peer, use its ca to establish a secure connection and deliver the secret
		for p := range peerCaCerts {
			err = sendSecret(p, peerCaCerts[p], trustBundle)
			if nil != err {
				// This is bad because one of the peers we just communicated with is dead
				log.Fatal("Failed to connect with peer: ", p)
			}
			log.Printf("Sent secret to peer: %s\n", p)
		}

		log.Fatalf("Finished ditribution of trust for CA with signature: %s\n", sig[:12])
	}

	log.Println("Not leader, waiting on provisioning.")

	<-finishedInit
	log.Println("Done.")
}
