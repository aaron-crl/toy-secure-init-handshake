## Basic Proof of Concept

- Client is hard coded to wait 5 seconds before connecting to server.
- Certs are hard coded to expire 600 seconds from startup.
- Certificates exist only in memory
- Server will listen forever

# Running the toy
To execute run the below commands in separate terminals.

**terminal 1**
`go run server.go client.go common.go --selfAddress=localhost:8443 --peerAddress=localhost:8444`

**terminal 2**
`go run server.go client.go common.go --selfAddress=localhost:8444 --peerAddress=localhost:8443`

This creates a server and client process and then reads the results of each's validation from the trustedPeers channel.

### common.go
Contains the handshake crypto and helper functions

### server.go
Contains the listener and startup code

### client.go
Contains the client process code