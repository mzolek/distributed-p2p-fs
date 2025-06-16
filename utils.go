// Authors: Krzysztof Żyndul, Marcin Żołek

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
)

type CryptoKeys struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

type MessageType uint8

const (
	Ping         MessageType = 0
	Hello        MessageType = 1
	RootRequest  MessageType = 2
	DatumRequest MessageType = 3
	Ok           MessageType = 128
	Error        MessageType = 129
	HelloReply   MessageType = 130
	RootReply    MessageType = 131
	Datum        MessageType = 132
	NoDatum      MessageType = 133
)

const (
	Chunk     = 0
	Directory = 1
	Big       = 2
)

const HeaderLength = 7 // Header is ID, Type, Length.

type Message struct {
	ID        uint32
	Type      MessageType
	Length    uint16
	Body      []byte
	Signed    bool // If Signed is true then Signature has length 32.
	Signature []byte
}

func failOnErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func printMessage(message Message, name string) {
	fmt.Println("Message: ", name)
	fmt.Println("-------------------------------")
	fmt.Println("ID: ", message.ID)
	fmt.Println("Type: ", message.Type)
	fmt.Println("Length: ", message.Length)
	fmt.Println("Body: ", string(message.Body))
	if message.Signed {
		fmt.Println("Signature: ", fmt.Sprintf("%x", message.Signature))
	} else {
		fmt.Println("Signature: Not signed")
	}
	fmt.Println("-------------------------------")
	fmt.Println()
}

func getExtensions(message Message) []byte {
	return message.Body[:4]
}

func getName(message Message) []byte {
	return message.Body[4:]
}

func getHash(message Message) [32]byte {
	return [32]byte(message.Body[:32])
}

func getDatumType(message Message) byte {
	return message.Body[32]
}

func getDatumValue(message Message) []byte {
	return message.Body[33:]
}

func getMessageWithoutSignature(message Message) []byte {
	bytes := messageToBytes(message)
	return bytes[:message.Length+HeaderLength]
}

func parseMessage(data []byte) (Message, error) {
	// TODO if message type is Datum check if correct format
	if len(data) < HeaderLength {
		return Message{}, errors.New("Message too short.")
	}

	id := binary.BigEndian.Uint32(data[0:4])
	typ := MessageType(data[4])
	length := int(binary.BigEndian.Uint16(data[5:7]))
	bodyEnd := HeaderLength + length

	if bodyEnd > len(data) {
		return Message{}, errors.New("Declared length exceeds data size.")
	}

	if (typ == Hello || typ == HelloReply) && length < 4 {
		return Message{}, errors.New("Body too short.")
	}

	body := data[HeaderLength:bodyEnd]

	var signed bool
	var signature []byte

	if typ == Hello || typ == HelloReply || typ == RootReply || typ == NoDatum { // || typ == Datum {
		if bodyEnd+64 > len(data) {
			return Message{}, errors.New("Missing signature.")
		}

		signed = true
		signature = data[bodyEnd:(bodyEnd + 64)]
	} else {
		signed = false
		signature = nil
	}

	message := Message{
		ID:        id,
		Type:      typ,
		Length:    uint16(length),
		Body:      body,
		Signed:    signed,
		Signature: signature,
	}

	return message, nil
}

func messageToBytes(message Message) []byte {
	header := make([]byte, HeaderLength)
	binary.BigEndian.PutUint32(header[0:4], message.ID)
	header[4] = byte(message.Type)

	length := uint16(len(message.Body))
	binary.BigEndian.PutUint16(header[5:7], length)

	data := make([]byte, 0)
	// TODO don't append use Buffer?
	data = append(data, header...)
	data = append(data, message.Body...)

	if message.Signed {
		data = append(data, message.Signature...)
	}

	return data
}

func createBytesNotSigned(id uint32, typ MessageType, body []byte) []byte {
	data := messageToBytes(Message{
		ID:        id,
		Type:      typ,
		Length:    uint16(len(body)),
		Body:      body,
		Signed:    false,
		Signature: nil,
	})

	return data
}

func createHelloBytes(id uint32, typ MessageType, extensions []byte, name []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	body := make([]byte, 0)
	body = append(body, extensions...)
	body = append(body, name...)

	data := messageToBytes(Message{
		ID:        id,
		Type:      typ,
		Length:    uint16(len(body)),
		Body:      body,
		Signed:    false,
		Signature: nil,
	})

	signature, err := computeSignature(data, privateKey)

	if err != nil {
		return nil, err
	}

	data = append(data, signature...)

	return data, nil
}

func checkHelloReplyMessage(message Message, id uint32, name string) bool {
	if message.Type == HelloReply && message.ID == id && message.Length >= 4 && string(message.Body[4:]) == name {
		return true
	}
	return false
}

// KEYS, SIGNATURES, ETC.

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

func bytesToPublicKey(key []byte) *ecdsa.PublicKey {
	var x, y big.Int
	x.SetBytes(key[:32])
	y.SetBytes(key[32:])
	publicKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     &x,
		Y:     &y,
	}
	return &publicKey
}

func computeSignature(data []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hashed := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature, err
}

func verifySignedMessage(sendMessage Message, receivedMessage Message, senderPublicKey *ecdsa.PublicKey) bool {
	// if sendMessage.ID != receivedMessage.ID {
	// 	return false
	// }

	payload := getMessageWithoutSignature(receivedMessage)
	fmt.Printf("[verifySignedMessage] Payload: %x\n", payload)
	printMessage(receivedMessage, "Received Message")

	return verifySignature(senderPublicKey, payload, receivedMessage.Signature)
}

func verifyDatum(sendMessage Message, receivedMessage Message, senderPublicKey *ecdsa.PublicKey) bool {

	if !verifySignedMessage(sendMessage, receivedMessage, senderPublicKey) {
		return false
	}

	if getHash(sendMessage) != getHash(receivedMessage) {
		return false
	}

	data := getDatumValue(receivedMessage)
	hash := sha256.Sum256(data)
	return hash != getHash(receivedMessage)
}

func verifySignature(publicKey *ecdsa.PublicKey, data []byte, signature []byte) bool {
	var r, s big.Int
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])
	hashed := sha256.Sum256(data)
	return ecdsa.Verify(publicKey, hashed[:], &r, &s)
}

func saveKeysToFile(keys CryptoKeys, filename string) error {
	privateKeyBytes := keys.PrivateKey.D.Bytes()
	publicKeyBytes := formatPublicKey(keys.PublicKey)

	data := append(privateKeyBytes, publicKeyBytes...)
	return writeToFile(data, filename)
}

func loadKeysFromFile(filename string) (CryptoKeys, error) {
	data, err := readFromFile(filename)
	if err != nil {
		return CryptoKeys{}, err
	}

	if len(data) < 32+64 {
		return CryptoKeys{}, errors.New("Invalid key file format")
	}

	privateKey := new(ecdsa.PrivateKey)
	privateKey.PublicKey.Curve = elliptic.P256()
	privateKey.D = new(big.Int).SetBytes(data[:32])
	publicKey := new(ecdsa.PublicKey)
	publicKey.Curve = elliptic.P256()
	publicKey.X = new(big.Int).SetBytes(data[32:64])
	publicKey.Y = new(big.Int).SetBytes(data[64:96])

	privateKey.PublicKey = *publicKey

	return CryptoKeys{privateKey, publicKey}, nil
}

func writeToFile(data []byte, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return err
	}
	return nil
}

func readFromFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data := make([]byte, 0)
	buf := make([]byte, 4096) // Read in chunks of 4096 bytes.
	for {
		n, err := file.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}

	return data, nil
}
