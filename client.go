package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

func runClient(peerAddress string, selfAddress string, lifespan time.Duration, secretToken []byte, trustedPeers chan initNode) {
	serviceTLSConf, err := createTLSConf(selfAddress, lifespan)
	if nil != err {
		log.Fatal("Creating service TLS configuration failed")
	}

	serviceTLSConf.InsecureSkipVerify = true

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: serviceTLSConf,
		},
	}

	// TODO replace this with a retry loop
	time.Sleep(5 * time.Second)

	// make initial connection to get server certificate
	conn, err := client.Get("https://" + peerAddress)
	if nil != err {
		log.Fatal(err)
	}

	// extract client and server certs for next steps
	clientCert := serviceTLSConf.Certificates[0].Certificate[0]
	serverCert := conn.TLS.PeerCertificates[0].Raw

	// generate challenge for the server
	sChallenge := generateServerChallenge(clientCert, serverCert, secretToken)
	challenge := serverChallenge{
		ClientAddress:     selfAddress,
		ClientCertificate: clientCert,
		Challenge:         sChallenge,
	}

	body := new(bytes.Buffer)
	json.NewEncoder(body).Encode(challenge)
	res, err := client.Post("https://"+peerAddress+"/challenge", "application/json; charset=utf-8", body)
	if nil != err {
		log.Fatal(err)
	}

	// Confirm that the server certificate has not changed
	if 0 != bytes.Compare(serverCert, res.TLS.PeerCertificates[0].Raw) {
		log.Fatal("Server certificate changed! Possible security issue.")
	}

	// read and validate server provided ack
	serverAck := clientAck{}
	json.NewDecoder(res.Body).Decode(&serverAck)
	if !validateClientAck(serverAck, clientCert, serverCert, secretToken) {
		log.Fatal("Failed to validate server certificate")
	}

	node := initNode{
		ClientAddress:     peerAddress,
		ClientCertificate: serverCert,
	}
	trustedPeers <- node

	fmt.Println("Client Success")
}
