// Authors: Marcin Żołek, Krzysztof Żyndul

package main

import (
    "fmt"
    "os"
    "log"
    "bytes"
    "io"
    "net/http"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    // "crypto/sha256"
    // "math/big"
)

// TYPES.

type CryptoKeys struct {
    privateKey *ecdsa.PrivateKey
    publicKey *ecdsa.PublicKey
}

// CONSTANTS.

// Server's URL.
const Server = "https://galene.org:8448"

// Types of message in peer-to-peer protocol.
const (
    Ping = 0
    Hello = 1
    RootRequest = 2
    DatumRequest = 3
    Ok = 128
    Error = 129
    HelloReply = 130
    RootReply = 131
    Datum = 132
    NoDatum = 133
)

// UTILS.

func failOnErr(err error) {
    if (err != nil) {
        log.Fatal(err)
    }
}

// Generates new random private key and generates public key from it.
// Returns custom struct CryptoKey.
func genCryptoKeys() CryptoKeys {
    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    failOnErr(err)
    publicKey := privateKey.Public().(*ecdsa.PublicKey)
    return CryptoKeys{privateKey, publicKey}
}

// Convert public key to bytes so that it can be sent.
func formatPublicKey(publicKey *ecdsa.PublicKey) []byte {
    formatted := make([]byte, 64)
    publicKey.X.FillBytes(formatted[:32])
    publicKey.Y.FillBytes(formatted[32:])
    return formatted
}

// CLIENT-SERVER PROTOCOL.

// 3.1
// Returns peers' names as slice of strings.
func getPeers() []string {
    resp, err := http.Get(Server + "/peers/")
    failOnErr(err)
    defer resp.Body.Close()
    body, err := io.ReadAll(resp.Body)
    failOnErr(err)
    names := make([]string, 0)
    for _, line := range bytes.Split(body, []byte("\n")) {
        names = append(names, string(line))
    }
    return names
}

// 3.2
// Makes PUT request with peer's public key (64 bytes) to register the peer.
func registerPeer(name string, key []byte) {
    resp, err := http.Post(Server + "/peers/" + name + "/key", "application/octet-stream", bytes.NewBuffer(key))
    failOnErr(err)
    defer resp.Body.Close()
}

// 3.3
// Returns slice of 64 bytes with public key of given peer.
func getKeyOfPeer(name string) []byte {
    resp, err := http.Get(Server + "/peers/" + name + "/key")
    failOnErr(err)
    defer resp.Body.Close()
    body, err := io.ReadAll(resp.Body)
    failOnErr(err)
    return body
}

// 3.4
// Returns addresses of given peer as slice of strings. These strings can be used in net.ResolveUDPAddr.
func getAddressesOfPeer(name string) []string {
    resp, err := http.Get(Server + "/peers/" + name + "/addresses")
    failOnErr(err)
    defer resp.Body.Close()
    body, err := io.ReadAll(resp.Body)
    failOnErr(err)
    addresses := make([]string, 0)
    for _, line := range bytes.Split(body, []byte("\n")) {
        addresses = append(addresses, string(line))
    }
    return addresses
}

// MAIN.

func main() {
    if len(os.Args) != 2 {
        fmt.Println("usage: ", os.Args[0] + " <name>")
        os.Exit(1)
    }

    name := os.Args[1]
    cryptoKeys := genCryptoKeys()

    // Example of usage.
    fmt.Println(name)
    names := getPeers()
    fmt.Println(names)
    key := getKeyOfPeer(names[0])
    fmt.Println(len(key)) // 64
    addresses := getAddressesOfPeer(names[0])
    fmt.Println(addresses[0])
    registerPeer(name, formatPublicKey(cryptoKeys.publicKey))
    names = getPeers()
    fmt.Println(names) // Still the same, because Hello, HelloReply is needed to register name.
}
