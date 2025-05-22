// Authors: Krzysztof Żyndul, Marcin Żołek

package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/big"
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
	ID          uint32
	Type        MessageType
	Length      uint16
	Body        []byte
	Signed      bool // If Signed is true then Signature has length 32.
	Signature   []byte
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
	fmt.Println("-------------------------------")
	fmt.Println()
}

func getExtensions(message Message) []byte {
	return message.Body[:4]
}

func getName(message Message) []byte {
	return message.Body[4:]
}

func getHash(message Message) []byte {
	return message.Body[:32]
}

func getDatumType(message Message) byte {
	return message.Body[32]
}

func getDatumValue(message Message) []byte {
	return message.Body[33:]
}

func parseMessage(data []byte) (Message, error) {
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

	if typ == Hello || typ == HelloReply || typ == RootReply { // || typ == Datum {
		if bodyEnd + 32 > len(data) {
			return Message{}, errors.New("Missing signature.")
		}

		signed = true
		signature = data[bodyEnd:(bodyEnd + 32)]
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
	publicKey := new(ecdsa.PublicKey)
	publicKey.Curve = elliptic.P256()
	publicKey.X.FillBytes(key[:32])
	publicKey.Y.FillBytes(key[32:])
	return publicKey
}

func computeSignature(data []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hashed := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature, err
}

// func verifyMessage(message BaseMessage, publicKey *ecdsa.PublicKey) bool {
// 	if message.Length != uint16(len(message.Payload)) {
// 		return false
// 	}
// 	if message.Sig == nil || len(message.Sig) != 64 {
// 		return false
// 	}
// 	return verifySignature(publicKey, message.Payload, message.Sig)
// }

func verifySignature(publicKey *ecdsa.PublicKey, data []byte, signature []byte) bool {
	var r, s big.Int
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])
	hashed := sha256.Sum256(data)
	return ecdsa.Verify(publicKey, hashed[:], &r, &s)
}
