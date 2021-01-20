## Basic Proof of Concept

- Client is hard coded to wait 5 seconds before connecting to server.
- Certs are hard coded to expire 600 seconds from startup.
- Certificates exist only in memory
- Server will listen forever

# Running the toy
To execute: `go run server.go client.go common.go`

This creates a server and client process and then reads the results of each's validation from the trustedPeers channel.

### common.go
Contains the handshake crypto and helper functions

### server.go
Contains the listener and startup code

### client.go
Contains the client process code