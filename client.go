// Authors: Marcin Żołek, Krzysztof Żyndul

package main

import (
	"bufio"
	"bytes"
	"log"
	"slices"
	"sync"
	//"crypto/ecdsa"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

// CONSTANTS.

// Server's URL.
const ServerURL = "https://galene.org:8448"
const ServerName = "galene.org"
const ServerPort = 8448

const SECRETS_FILES = ".keys"

type PeerInfo struct {
	Name         string
	Addr         *net.UDPAddr
	Wg           sync.WaitGroup
	IsUniqueChan chan bool
	HelloChan    chan struct{}
	RootChan     chan Message
	// SendHashChan chan []byte
	recvDatum chan Message
}

type NetInfo struct {
	Bytes []byte
	Addr  *net.UDPAddr
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
	req, err := http.NewRequest(http.MethodPut, ServerURL+"/peers/"+name+"/key", bytes.NewBuffer(key))
	failOnErr(err)
	client := &http.Client{}
	resp, err := client.Do(req)
	failOnErr(err)
	defer resp.Body.Close()
}

// 3.3
// Returns slice of 64 bytes with public key of given peer.
// TODO cant fail on error
func getKeyOfPeer(name string) ([]byte, error) {
	resp, err := http.Get(ServerURL + "/peers/" + name + "/key")
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// 3.4
// Returns addresses of given peer as slice of strings. These strings can be used in net.ResolveUDPAddr.
func getAddressesOfPeer(name string) []string {
	resp, err := http.Get(ServerURL + "/peers/" + name + "/addresses")
	failOnErr(err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return make([]string, 0)
	}
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
	buffer := make([]byte, 65536)

	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Read error:", err)
			continue
		}
		//fmt.Printf("Received from %s: %s\n", addr.String(), string(buffer[:n]))
		readChan <- NetInfo{buffer[:n], addr}
	}
}

func writer(conn *net.UDPConn, writeChan chan NetInfo) {
	for toSend := range writeChan {
		conn.WriteToUDP(toSend.Bytes, toSend.Addr)
	}
}

func respondToHello(writeChan chan NetInfo, peerName string, peerAddr *net.UDPAddr, message Message,
	name string, cryptoKeys CryptoKeys) {

	keysBytes, err := getKeyOfPeer(peerName)
	if err != nil {
		fmt.Println("Error getting public key of peer:", peerName, "-", err)
		return
	}

	peerPublicKey := bytesToPublicKey(keysBytes)
	// TODO we should pass id of message we send to peer as first arg currently
	// we cant do that
	isCorrect := verifySignedMessage(message, message, peerPublicKey)
	if !isCorrect {
		fmt.Println("Received Hello from", peerName, "with incorrect signature.")
		return
	}

	// verify if message.Signature is correct with peerPublicKey.
	// if yes then create and send HelloReply:
	helloReplyBytes, err := createHelloBytes(message.ID, HelloReply, getExtensions(message), []byte(name), cryptoKeys.PrivateKey) // Using my name, not peer name in HelloReply.
	if err == nil {
		writeChan <- NetInfo{helloReplyBytes, peerAddr} // Don't check errors or retransmit, because if HelloReply doesn't reach the peer, the peer will send Hello again.
	}
}

func talkToPeer(writeChan chan NetInfo, peerInfoChan chan *PeerInfo, finishCommChan chan string,
	peerName string, name string, cryptoKeys CryptoKeys, myAddr *net.UDPAddr, init bool) {
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
	peerPublicKeyBytes, err := getKeyOfPeer(peerName)
	if err != nil {
		fmt.Println("Error getting public key of peer:", peerName, "-", err)
		return
	}
	fmt.Printf("Peer %s has public key: %x, length: %d\n", peerName, peerPublicKeyBytes, len(peerPublicKeyBytes))
	peerPublicKey := bytesToPublicKey(peerPublicKeyBytes)

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

	// main ->
	isUniqueChan := make(chan bool)
	helloChan := make(chan struct{})
	rootChan := make(chan Message)
	recvDatum := make(chan Message)
	// sendHashChan := make(chan []byte)

	// peerInfoChan <- &PeerInfo{Name: peerName, Addr: peerAddr, IsUniqueChan: isUniqueChan, HelloChan: helloChan, RootChan: rootChan, SendHashChan: sendHashChan, recvDatum: recvDatum}
	peerInfoChan <- &PeerInfo{Name: peerName, Addr: peerAddr, IsUniqueChan: isUniqueChan, HelloChan: helloChan, RootChan: rootChan, recvDatum: recvDatum}
	isUnique := <-isUniqueChan

	if !isUnique {
		fmt.Println("Communication with", peerName, "is already being handled. Please be patient.")
		return
	}

	// NAT traversal
	if peerName != ServerName {
		serverAddrs := getAddressesOfPeer(ServerName)
		serverAddr, _ := net.ResolveUDPAddr("udp", serverAddrs[0])
		natBytes := createBytesNotSigned(42, NatTraversalRequest, udpAddrToBytes(peerAddr)) // myAddr też nie działa
		writeChan <- NetInfo{natBytes, serverAddr}
		fmt.Printf("NatTraversalRequest")
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

	if init { // Init = true means we don't want to talk now, just hello server when starting program.
		finishCommChan <- peerAddr.String()
		return
	}

	rootRequestBytes := createBytesNotSigned(rand.Uint32(), RootRequest, make([]byte, 32))

	rootTicker := time.NewTicker(1 * time.Second)
	var rootHash []byte
rootLoop:
	for {
		select {
		case <-rootTicker.C:
			fmt.Println("Sending RootRequest to", peerName)
			writeChan <- NetInfo{rootRequestBytes, peerAddr}
		case rootMessage := <-rootChan:

			if !verifySignedMessage(rootMessage, rootMessage, peerPublicKey) {
				fmt.Println("Received RootReply from", peerName, "with incorrect signature.")
				return
			}
			rootHash = rootMessage.Body
			rootTicker.Stop()
			fmt.Println("Got RootReply from", peerName)
			break rootLoop
		}
	}

	// fmt.Println("Root hash is:", rootHash)

	// received := make(map[string]struct{}) // map of hashes of data that we have already received.
	needed := make(map[[32]byte]struct{}) // map of hashes of data that we need to receive.
	needed[[32]byte(rootHash)] = struct{}{}

	// filesSystemGuard := newNode([]byte{}, Directory, nil, "")
	root := newNode(rootHash, 0, nil, "/")
	// filesSystemGuard.AddChild(root)

	hashToNodeMap := make(map[[32]byte]*Node) // map of hashes to nodes, used to build Merkle Tree.
	hashToNodeMap[[32]byte(rootHash)] = root

	datumTicker := time.NewTicker(100 * time.Millisecond)

	for {
		select {
		//
		case <-datumTicker.C:
			if len(needed) > 0 {
				for hash, _ := range needed {
					datumRequestBytes := createBytesNotSigned(rand.Uint32(), DatumRequest, hash[:])
					writeChan <- NetInfo{datumRequestBytes, peerAddr}
					break
				}
			} else {
				// TODO why do we stop here? When we have all data, we should add user file system traversal.
				// We have all data. Cleaning.
				datumTicker.Stop()
				finishCommChan <- peerAddr.String()
				fileSystem, err := buildFileSystem(root)
				if err != nil {
					fmt.Println("Error building file system:", err)
					return
				}

				printFileSystem(fileSystem, "")

				for i := 0; i < len(fileSystem.Directories[0].Files); i++ {
					printTextFile(fileSystem.Directories[0].Files[i])
				}
				for i := 0; i < len(fileSystem.Directories[1].Files); i++ {
					fmt.Println("File:", fileSystem.Directories[1].Files[i].Name)
					err = saveImageTooDisk(fileSystem.Directories[1].Files[i], "output_"+strconv.Itoa(i)+".jpeg")
					if err != nil {
						fmt.Println("Error saving file to disk:", err)
					}
				}

				// err = saveImageTooDisk(fileSystem.Directories[1].Files[1], "output.jpeg")
				// if err != nil {
				// 	fmt.Println("Error saving image to disk:", err)
				// }

				return
			}

		case message := <-recvDatum:
			// fmt.Println("Received Datum with hash:", getHash(message))

			if message.Type == NoDatum {
				if !verifySignedMessage(message, message, peerPublicKey) {
					delete(needed, getHash(message))
					continue
				}
			}

			fmt.Print("HERE\n")

			_, ok := needed[getHash(message)]
			if ok && verifyDatum(message, message) {
				fmt.Print("CORRECT\n")

				processNode(message, hashToNodeMap, needed)
				delete(needed, getHash(message))
			}
		}
	}

}

func userInterface(writeChan chan NetInfo, peerInfoChan chan *PeerInfo, finishCommChan chan string, name string, cryptoKeys CryptoKeys, myAddr *net.UDPAddr) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		peerName := scanner.Text()
		fmt.Println("User wants to talk to:", peerName)
		go talkToPeer(writeChan, peerInfoChan, finishCommChan, peerName, name, cryptoKeys, myAddr, false)
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
	isNameTaken := slices.Contains(names, name)
	fmt.Println("All peers before registration by HTTPS: ", names)
	addresses := getAddressesOfPeer(name)
	fmt.Println("My addresses known by server before registraton by UDP: ", addresses)
	cryptoKeys := CryptoKeys{}

	// TODO implicitly register with server
	if len(addresses) != 0 || isNameTaken {
		fmt.Println("Trying loading keys from file.")
		cryptoKeys, err = loadKeysFromFile(SECRETS_FILES)
		if err != nil {
			fmt.Println("No valid keys found. Please register again under different name.")
			os.Exit(1)
		}
		publicKeyOnServer, _ := getKeyOfPeer(name)
		if !bytes.Equal(publicKeyOnServer, formatPublicKey(cryptoKeys.PublicKey)) {
			fmt.Println("Name is already registered. Please register under different name.")
			os.Exit(1)
		}
	} else {
		fmt.Println("Generating keys.")
		cryptoKeys = genCryptoKeys()
		if err := saveKeysToFile(cryptoKeys, SECRETS_FILES); err != nil {
			fmt.Println("Failed to save keys to file:", err)
		}
		registerPeer(name, formatPublicKey(cryptoKeys.PublicKey))
	}

	names = getPeers()
	fmt.Println("All peers after registration by HTTPS ", names)
	serverAddr, _ := net.ResolveUDPAddr("udp", getAddressesOfPeer(ServerName)[0])

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

	readChan := make(chan NetInfo)       // Channel to read from UDP.
	writeChan := make(chan NetInfo)      // Channel to write to UDP.
	peerInfoChan := make(chan *PeerInfo) // Channel to inform main thread that we want to communcate with new peer.
	finishCommChan := make(chan string)  // Channel to signal to main thread that communication with peer has finished (all data received).

	go reader(conn, readChan)
	go writer(conn, writeChan)
	go talkToPeer(writeChan, peerInfoChan, finishCommChan, ServerName, name, cryptoKeys, &addr, true) // Hello to server.
	go userInterface(writeChan, peerInfoChan, finishCommChan, name, cryptoKeys, &addr)

	pingTicker := time.NewTicker(60 * time.Second)

	for {
		select {
		case <-pingTicker.C: // Ping server every minute.
			pingBytes := createBytesNotSigned(42, Ping, make([]byte, 0))
			go func(netInfo NetInfo) { writeChan <- netInfo }(NetInfo{pingBytes, serverAddr})
		case peerInfo := <-peerInfoChan:
			_, ok := peersMap[peerInfo.Addr.String()]
			if ok {
				go func(peerInfo *PeerInfo) { peerInfo.IsUniqueChan <- false }(peerInfo) // If this peer is currently being processed by different goroutine then don't create new.
			} else {
				peersMap[peerInfo.Addr.String()] = peerInfo
				go func(peerInfo *PeerInfo) { peerInfo.IsUniqueChan <- true }(peerInfo)
			}
		case peerAddrStr := <-finishCommChan:
			peerInfo := peersMap[peerAddrStr]
			delete(peersMap, peerAddrStr)

			go func(peerInfo *PeerInfo) {
				peerInfo.Wg.Wait()
				close(peerInfo.HelloChan)
				close(peerInfo.RootChan)
			}(peerInfo)
			go func(peerInfo *PeerInfo) {
				for range peerInfo.HelloChan {
				}
			}(peerInfo)
			go func(peerInfo *PeerInfo) {
				for range peerInfo.RootChan {
				}
			}(peerInfo)

			fmt.Println("Communication finished with", peerInfo.Name)
		case netInfo := <-readChan:
			message, err := parseMessage(netInfo.Bytes)
			peerAddr := netInfo.Addr

			if err != nil {
				fmt.Println("Unknown message:", err)
				continue
			}

			// printMessage(message, "Message")

			switch message.Type {
			case Hello:
				go respondToHello(writeChan, string(getName(message)), peerAddr, message, name, cryptoKeys)
			case HelloReply:
				peerInfo, ok := peersMap[peerAddr.String()]
				if ok {
					peerInfo.Wg.Add(1)
					go func(peerInfo *PeerInfo) {
						defer peerInfo.Wg.Done()
						peerInfo.HelloChan <- struct{}{} // Send through channel that we got HelloReply.
					}(peerInfo)
				}
			case Ping:
				okBytes := createBytesNotSigned(message.ID, Ok, make([]byte, 0))
				go func(netInfo NetInfo) { writeChan <- netInfo }(NetInfo{okBytes, peerAddr})
			case NatTraversalRequest2:
				fmt.Printf("NatTraversalRequest2")
				okBytes := createBytesNotSigned(message.ID, Ok, make([]byte, 0))
				pingBytes := createBytesNotSigned(message.ID, Ping, make([]byte, 0))
				truePeerAddr, err := bytesToUDPAddr(message.Body)
				if err != nil {
					fmt.Println("Error:", err)
				} else {
					go func(netInfoOk NetInfo, netInfoPing NetInfo) {
						writeChan <- netInfoOk
						writeChan <- netInfoPing
					}(NetInfo{okBytes, peerAddr}, NetInfo{pingBytes, truePeerAddr})
				}
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
					go func(peerInfo *PeerInfo, message Message) {
						defer peerInfo.Wg.Done()
						peerInfo.RootChan <- message // Send through channel that we got RootReply.
					}(peerInfo, message)
				}
			case DatumRequest:
				// TODO - wisienka na torcie, wysyłanie w kawałkach itp.
			case Datum, NoDatum:
				// TODO sprawdzanie podpisów i poprawności hasha. Tworzenie na bieżąco Merkle Tree (na razie po prostu wyświetlam wszytko).
				peerInfo, ok := peersMap[peerAddr.String()]
				if ok {
					peerInfo.recvDatum <- message
				}
				// case NoDatum:
				// 	fmt.Println("No datum with hash:", getHash(message))
				// 	peerInfo, ok := peersMap[peerAddr.String()]
				// 	if ok {
				// 		// recvHash := getHash(message)
				// 		peerInfo.recvDatum <- message
				// 	}
			}
		}

		// Tego poniżej nie powinno tu być, ale może się przydać do debugowania, więc jest.
		//fmt.Println("My addresses known by server after registration by UDP: ", getAddressesOfPeer(name))
	}
}
