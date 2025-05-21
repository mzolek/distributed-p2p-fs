// Authors: Marcin Żołek, Krzysztof Żyndul

package main

import (
	"bytes"
	"bufio"
	"sync"
	"slices"
	"crypto/ecdsa"
	"fmt"
	"io"
	"net"
	"log"
	"net/http"
	"math/rand"
	"os"
	"time"
	"strconv"
)

// CONSTANTS.

// Server's URL.
const ServerURL = "https://galene.org:8448"
const ServerName = "galene.org"
const ServerPort = 8448

type PeerInfo struct {
	Name string
	HelloChan chan struct{}
}

// CLIENT-SERVER PROTOCOL.

// 3.1
// Returns peers' names as slice of strings.
func getPeers() []string {
	resp, err := http.Get(ServerURL + "/peers/")
	failOnErr(err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	failOnErr(err)
	names := make([]string, 0)
	for _, line := range bytes.Split(body, []byte("\n")) {
		if len(line) != 0 {
			names = append(names, string(line))
		}
	}
	return names
}

// 3.2
// Makes PUT request with peer's public key (64 bytes) to register the peer.
func registerPeer(name string, key []byte) {
	fmt.Println("name: ", name)
	req, err := http.NewRequest(http.MethodPut, ServerURL + "/peers/" + name + "/key", bytes.NewBuffer(key))
	failOnErr(err)
	client := &http.Client{}
	resp, err := client.Do(req)
	failOnErr(err)
	defer resp.Body.Close()
}

// 3.3
// Returns slice of 64 bytes with public key of given peer.
func getKeyOfPeer(name string) []byte {
	resp, err := http.Get(ServerURL + "/peers/" + name + "/key")
	failOnErr(err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	failOnErr(err)
	return body
}

// 3.4
// Returns addresses of given peer as slice of strings. These strings can be used in net.ResolveUDPAddr.
func getAddressesOfPeer(name string) []string {
	resp, err := http.Get(ServerURL + "/peers/" + name + "/addresses")
	failOnErr(err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	failOnErr(err)
	addresses := make([]string, 0)
	for _, line := range bytes.Split(body, []byte("\n")) {
		if len(line) != 0 {
			addresses = append(addresses, string(line))
		}
	}
	return addresses
}

// Send Hello to server and receive HelloReply.
// Hello from server is listened in main loop, not here, because it is the same as other Hello messages from other peers.
func registerIP(conn *net.UDPConn, name string, privateKey *ecdsa.PrivateKey) {
	// Server address.
	addresses := getAddressesOfPeer(ServerName)
	if len(addresses) == 0 {
		log.Fatal("No server UDP address is available.")
	}
	serverAddr, err := net.ResolveUDPAddr("udp", addresses[0])
	failOnErr(err)
	// Create hello message.
	id := rand.Uint32()
	helloBytes, err := createHelloBytes(id, Hello, make([]byte, 4), []byte(name), privateKey)
	failOnErr(err)
	// Send Hello and receive HelloReply.
	buffer := make([]byte, 1024)
	timeout := 5 * time.Second
	maxRetries := 10
	for i := 1; i <= maxRetries; i++ {
		_, err = conn.WriteToUDP(helloBytes, serverAddr)
		if err != nil {
			continue
		}
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Registration attempt %d/%d failed: %v\n", i, maxRetries, err)
			continue
		}

		helloReplyMessage, err := parseMessage(buffer[:n])
		if err != nil || !checkHelloReplyMessage(helloReplyMessage, id, ServerName) {
			fmt.Fprintf(os.Stderr, "Registration attempt %d/%d failed:\n", i, maxRetries)
			printMessage(helloReplyMessage, "HelloReply from server")
			continue
		}

		printMessage(helloReplyMessage, "HelloReply from server")

		return
	}

	log.Fatal("Registration failed miserably")
}

func respondToHello(conn *net.UDPConn, peerName string, peerAddr *net.UDPAddr, message Message,
					name string, cryptoKeys CryptoKeys, peers *sync.Map) {
	// TODO
	// peerPublicKey := getKeyOfPeer(peerName)
	// verify if message.Signature is correct with peerPublicKey.
	// if yes then create and send HelloReply:
	helloReplyBytes, err := createHelloBytes(message.ID, HelloReply, getExtensions(message), []byte(name), cryptoKeys.PrivateKey) // Using my name, not peer name in HelloReply.
	if err == nil {
		peers.Store(peerAddr.String(), &PeerInfo{Name: peerName, HelloChan: make(chan struct{})})
		conn.WriteToUDP(helloReplyBytes, peerAddr) // Don't check errors or retransmit, because if HelloReply doesn't reach the peer, the peer will send Hello again.
	}
}

func talkToPeer(conn *net.UDPConn, peerName string, name string, cryptoKeys CryptoKeys, peers *sync.Map) {
	allPeers := getPeers()
	if !slices.Contains(allPeers, peerName) { // Check if this peer exists.
		fmt.Println("Peer", peerName, "does not exist.")
		return
	}
	addresses := getAddressesOfPeer(peerName)
	if len(addresses) == 0 {
		fmt.Println("Peer", peerName, "does not have any UDP address.")
		return
	}
	peerAddr, err := net.ResolveUDPAddr("udp", addresses[0])
	if err != nil {
		fmt.Println("Incorrect address.")
		return
	}
	fmt.Println(peerName, "has address:", peerAddr.String())

	helloReplyBytes, err := createHelloBytes(42, Hello, make([]byte, 4), []byte(name), cryptoKeys.PrivateKey)
	if err != nil {
		fmt.Println("Can't create Hello to peer", peerName)
		return
	}
	helloChan := make(chan struct{})
	peers.Store(peerAddr.String(), &PeerInfo{Name: peerName, HelloChan: helloChan})
	ticker := time.NewTicker(2 * time.Second)

	for {
		select {
		case <-ticker.C:
			fmt.Println("Sending Hello to", peerName)
			conn.WriteToUDP(helloReplyBytes, peerAddr)
		case <-helloChan:
			ticker.Stop()
			fmt.Println("Got HelloReply from", peerName)
			//TODO
			fmt.Println("TODO: Further communication with", peerName)
			// Trzeba zaznaczyć w zmiennej lokalnej, że helloReply zrobione i dodać kolejne case do select.
			// Trzeba dalej odbierać w select <-helloChan i nic z tym nie robić, bo inaczej będą wycieki funkcji goroutine (wredny peer może nam w kóło wysyłać HelloReply i głowna pętla będzie w kółko tworzyć nowe goroutines, które będą wrzucać w kanał coś i się blokować).
			// Po zakończeniu całej komunikacji z Peerem usuniemy peera z mapy peers (żeby pętla głowna nie tworzyła już nowych gorutines na HelloReply itp.)
			// i osuszymy kanały (wyjmiemy z nich wszystko, żeby odblokować wszystkie wstrzymane gorutines).
			// I to powinno zadziałać :-), aczkolwiek trochę skomplikowane.
		}
	}
}

func userInterface(conn *net.UDPConn, name string, cryptoKeys CryptoKeys, peers *sync.Map) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		peerName := scanner.Text()
		fmt.Println("User wants to talk to:", peerName)
		go talkToPeer(conn, peerName, name, cryptoKeys, peers)
	}
}

// MAIN.

func main() {
	if len(os.Args) != 3 {
		fmt.Println("usage: ", os.Args[0]+" <name> <port>")
		os.Exit(1)
	}
	name := os.Args[1]
	portStr := os.Args[2]
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		log.Fatal("Invalid port number:", portStr)
	}

	fmt.Println("My name: ", name)
	fmt.Println("My port: ", port)

	rand.Seed(time.Now().UnixNano()) // Seed for random IDs.

	// Example of usage.
	names := getPeers()
	fmt.Println("All peers before registration by HTTPS: ", names)
	addresses := getAddressesOfPeer(name)
	fmt.Println("My addresses known by server before registraton by UDP: ", addresses)

	cryptoKeys := genCryptoKeys()
	registerPeer(name, formatPublicKey(cryptoKeys.PublicKey))
	names = getPeers()
	fmt.Println("All peers after registration by HTTPS ", names)

	addr := net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: port,
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatal("Failed to bind: ", err)
	}
	defer conn.Close()

	registerIP(conn, name, cryptoKeys.PrivateKey)

	fmt.Println("Listening on", addr.String())

	buffer := make([]byte, 1024)

	var peers sync.Map // Thread-safe dictionary that contains keys: peer's addresses (as strings) and values: pointers to PeerInfo struct

	go userInterface(conn, name, cryptoKeys, &peers)

	conn.SetReadDeadline(time.Time{}) // Infinite timeout for below ReadFromUDP.

	for {
		n, peerAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Read error:", err)
			continue
		}
		fmt.Printf("Received from %s: %s\n", peerAddr.String(), string(buffer[:n]))

		message, err := parseMessage(buffer[:n])

		if err != nil {
			fmt.Println("Unknown message.")
			continue
		}

		printMessage(message, "Message")

		switch message.Type {
			case Hello:
				peerName := getName(message)
				if peerName == nil {
					fmt.Printf("No name peer")
					continue
				}
				go respondToHello(conn, string(peerName), peerAddr, message, name, cryptoKeys, &peers)
			case HelloReply:
				val, ok := peers.Load(peerAddr.String())
				if ok {
					peerInfo := val.(*PeerInfo)
					go func() { peerInfo.HelloChan <- struct{}{} }() // Send through channel that we got HelloReply.
				}
			case Ping:
				/*val, ok := peers.Load(peerAddr.String())
				if ok { // Check if last ping was max 4 minutes ago.
					peerInfo := val.(*PeerInfo)
					now := time.Now().Unix();
					if now - peerInfo.Ping <= 4 * 60 {
						peerInfo.Ping = now
						okBytes := createPingBytes(rand.Uint32(), Ok)
						conn.WriteToUDP(okBytes, peerAddr)
					}
				}*/
			case Ok:
				fmt.Println("Received Ok from ", peerAddr.String())
				// Do nothing?
			case Error:
				fmt.Println("Received Error from ", peerAddr.String())
				// Trzeba zobaczyć o co z tym chodzi. Do czego ten Error jest używany i jak powinien być obsługiwany?
			case RootRequest:
				// TODO - analogicznie do obsługi Hello
			case RootReply:
				// TODO - analogicznie do obsługi HelloReply
			case DatumRequest:
				// TODO - wisienka na torcie, wysyłanie w kawałkach itp.
			case Datum:
				// TODO
			case NoDatum:
				// TODO
		}

		//time.Sleep(1 * time.Second)
		//fmt.Println("My addresses known by server after registration by UDP: ", getAddressesOfPeer(name))
	}
}
