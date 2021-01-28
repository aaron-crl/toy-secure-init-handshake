## An approch for establishing a common CA given a shared secret

This toy demonstrates an approach for establishing common trust via n-way mutual-authenticated TLS public key exchange.

**Initial Trust**
* Each node creates a listener process then makes initialization requests to each listed peer.
* Each request includes a challenge comprised of an HMAC of the requesters hostname and ephemeral CA public key.
* The responder verifies the HMAC of the challenge before saving the public key and responding to the requester with an aknowledgement containing its own hostname and CA public key.

**Provisioning**
Once all peers have exchanged public keys. The node with the lowest signature (by go string compare) creates an initial inter-node CA, generates an HMAC of it, then distributes it to all peers via TLS using the public keys exchanged during the initial trust phase.

### Other notes
- Init Certificates exist only in memory


# Running the toy
To execute run the below commands in separate terminals.

**terminal 1**
`go run server.go client.go common.go --selfAddress=localhost:8443 --peerAddresses=localhost:8444,localhost:8445 --numNodes=3`

**terminal 2**
`go run server.go client.go common.go --selfAddress=localhost:8444 --peerAddress=localhost:8443,localhost:8445 --numNodes=3`

**terminal 3**
`go run server.go client.go common.go --selfAddress=localhost:8445 --peerAddress=localhost:8443,localhost:8444 --numNodes=3`

This creates a server and client process and then reads the results of each's validation from the trustedPeers channel.

### common.go
Contains the handshake crypto and helper functions and structs

### server.go
Contains the listener and startup code

### client.go
Contains the client process code