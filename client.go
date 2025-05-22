// Authors: Marcin Żołek, Krzysztof Żyndul

package main

import (
	"bytes"
	"bufio"
	"slices"
	"sync"
	//"crypto/ecdsa"
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
	Addr *net.UDPAddr
	Wg sync.WaitGroup
	IsUniqueChan chan bool
	HelloChan chan struct{}
	RootChan chan []byte
}

type NetInfo struct {
	Bytes []byte
	Addr *net.UDPAddr
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

func reader(conn *net.UDPConn, readChan chan NetInfo) {
	buffer := make([]byte, 1024)

	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Read error:", err)
			continue
		}
		fmt.Printf("Received from %s: %s\n", addr.String(), string(buffer[:n]))
		readChan <- NetInfo{ buffer[:n], addr }
	}
}

func writer(conn *net.UDPConn, writeChan chan NetInfo) {
	for toSend := range writeChan {
		conn.WriteToUDP(toSend.Bytes, toSend.Addr)
	}
}

func respondToHello(writeChan chan NetInfo, peerName string, peerAddr *net.UDPAddr, message Message,
					name string, cryptoKeys CryptoKeys) {
	// TODO
	// peerPublicKey := getKeyOfPeer(peerName)
	// verify if message.Signature is correct with peerPublicKey.
	// if yes then create and send HelloReply:
	helloReplyBytes, err := createHelloBytes(message.ID, HelloReply, getExtensions(message), []byte(name), cryptoKeys.PrivateKey) // Using my name, not peer name in HelloReply.
	if err == nil {
		writeChan <- NetInfo{helloReplyBytes, peerAddr} // Don't check errors or retransmit, because if HelloReply doesn't reach the peer, the peer will send Hello again.
	}
}

func talkToPeer(writeChan chan NetInfo, peerInfoChan chan *PeerInfo, finishCommChan chan string,
				peerName string, name string, cryptoKeys CryptoKeys) {
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

	helloBytes, err := createHelloBytes(rand.Uint32(), Hello, make([]byte, 4), []byte(name), cryptoKeys.PrivateKey)
	if err != nil {
		fmt.Println("Can't create Hello to peer", peerName)
		return
	}

	isUniqueChan := make(chan bool)
	helloChan := make(chan struct{})
	rootChan := make(chan []byte)

	peerInfoChan <- &PeerInfo{Name: peerName, Addr: peerAddr, IsUniqueChan: isUniqueChan, HelloChan: helloChan, RootChan: rootChan}
	isUnique := <- isUniqueChan

	if !isUnique {
		fmt.Println("Communcation with", peerName, "is already being handled. Please be patient.")
		return
	}

	helloTicker := time.NewTicker(2 * time.Second)
helloLoop:
	for {
		select {
		case <-helloTicker.C:
			fmt.Println("Sending Hello to", peerName)
			writeChan <- NetInfo{helloBytes, peerAddr}
		case <-helloChan:
			helloTicker.Stop()
			fmt.Println("Got HelloReply from", peerName)
			break helloLoop
		}
	}

	rootRequestBytes := createEmptyBodyBytes(rand.Uint32(), RootRequest, 32)

	rootTicker := time.NewTicker(1 * time.Second)
	var rootHash []byte
rootLoop:
	for {
		select {
		case <-rootTicker.C:
			fmt.Println("Sending RootRequest to", peerName)
			writeChan <- NetInfo{rootRequestBytes, peerAddr}
		case rootHash = <-rootChan:
			rootTicker.Stop()
			fmt.Println("Got RootReply from", peerName)
			break rootLoop
		}
	}

	fmt.Println("Root hash is:", string(rootHash))

	//TODO Datum etc.
	fmt.Println("TODO: Further communication with", peerName)


	// Epilog.
	finishCommChan <- peerAddr.String()
}

func userInterface(writeChan chan NetInfo, peerInfoChan chan *PeerInfo, finishCommChan chan string, name string, cryptoKeys CryptoKeys) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		peerName := scanner.Text()
		fmt.Println("User wants to talk to:", peerName)
		go talkToPeer(writeChan, peerInfoChan, finishCommChan, peerName, name, cryptoKeys)
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
	fmt.Println("Listening on", addr.String())

	peersMap := make(map[string]*PeerInfo) // It is used only by main thread, so it does not have to be thread-safe.

	readChan := make(chan NetInfo) // Channel to read from UDP.
	writeChan := make(chan NetInfo) // Channel to write to UDP.
	peerInfoChan := make(chan *PeerInfo) // Channel to inform main thread that we want to communcate with new peer.
	finishCommChan := make(chan string) // Channel to signal to main thread that communication with peer has finished (all data received).

	go reader(conn, readChan)
	go writer(conn, writeChan)
	go userInterface(writeChan, peerInfoChan, finishCommChan, name, cryptoKeys)

	for {
		select {
		case peerInfo := <- peerInfoChan:
			_, ok := peersMap[peerInfo.Addr.String()]
			if ok {
				go func() { peerInfo.IsUniqueChan <- false }() // If this peer is currently being processed by different goroutine then don't create new.
			} else {
				peersMap[peerInfo.Addr.String()] = peerInfo
				go func() { peerInfo.IsUniqueChan <- true }()
			}
		case peerAddrStr := <- finishCommChan:
			peerInfo := peersMap[peerAddrStr]
			delete(peersMap, peerAddrStr)

			go func() {
				peerInfo.Wg.Wait()
				close(peerInfo.HelloChan)
				close(peerInfo.RootChan)
				fmt.Println("Communication with", peerInfo.Name, "is done 1.")
			}()
			go func() {
				for range peerInfo.HelloChan {}
				fmt.Println("Communication with", peerInfo.Name, "is done 2.")
			}()
			go func() {
				for range peerInfo.RootChan {}
				fmt.Println("Communication with", peerInfo.Name, "is done 3.")
			}()
		case netInfo := <-readChan:
			message, err := parseMessage(netInfo.Bytes)
			peerAddr := netInfo.Addr

			if err != nil {
				fmt.Println("Unknown message:", err)
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
				go respondToHello(writeChan, string(peerName), peerAddr, message, name, cryptoKeys)
			case HelloReply:
				peerInfo, ok := peersMap[peerAddr.String()]
				if ok {
					peerInfo.Wg.Add(1)
					go func() {
						defer peerInfo.Wg.Done()
						peerInfo.HelloChan <- struct{}{} // Send through channel that we got HelloReply.
					}()
				}
			case Ping:
				okBytes := createEmptyBodyBytes(message.ID, Ok, 0)
				go func() { writeChan <- NetInfo{ okBytes, peerAddr } }()
			case Ok:
				// Do nothing?
			case Error:
				fmt.Println("Received Error from ", peerAddr.String(), ": ", string(message.Body))
			case RootRequest:
				// TODO - analogicznie do obsługi Hello
			case RootReply:
				peerInfo, ok := peersMap[peerAddr.String()]
				if ok {
					peerInfo.Wg.Add(1)
					go func() {
						defer peerInfo.Wg.Done()
						peerInfo.RootChan <- message.Body // Send through channel that we got RootReply.
					}()
				}
			case DatumRequest:
				// TODO - wisienka na torcie, wysyłanie w kawałkach itp.
			case Datum:
				// TODO
			case NoDatum:
				// TODO
			}
		}

		// Tego poniżej nie powinno tu być, ale może się przydać do debugowania, więc jest.
		//fmt.Println("My addresses known by server after registration by UDP: ", getAddressesOfPeer(name))
	}
}
