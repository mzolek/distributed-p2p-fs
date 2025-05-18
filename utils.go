package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/big"
)

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

type BaseMessage struct {
	ID      uint32
	Type    MessageType
	Length  uint16
	Payload []byte
	Sig     []byte
}

type HelloMessage struct {
	BaseMessage
	Extensions []byte
	Name       []byte
}

// UTILS.
func failOnErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func printMessage(message BaseMessage, name string) {
	fmt.Println("Message from: ", name)
	fmt.Println("-------------------------------")
	fmt.Println("ID: ", message.ID)
	fmt.Println("Type: ", message.Type)
	fmt.Println("Length: ", message.Length)
	fmt.Println("Payload: ", message.Payload)
	fmt.Println("-------------------------------")
	fmt.Println()
}

func printHelloMessage(message HelloMessage, name string) {
	fmt.Println("Message from: ", name)
	fmt.Println("-------------------------------")
	fmt.Println("ID: ", message.ID)
	fmt.Println("Type: ", message.Type)
	fmt.Println("Length: ", message.Length)
	fmt.Println("Extensions: ", message.Extensions)
	fmt.Println("Name: ", message.Name)
	fmt.Println("-------------------------------")
	fmt.Println()
}

func parseMessage(data []byte) (BaseMessage, error) {
	headerLength := 7
	if len(data) < headerLength {
		return BaseMessage{}, errors.New("Wrong message format. Message too short")
	}

	id := binary.BigEndian.Uint32(data[0:4])
	typ := MessageType(data[4])
	length := int(binary.BigEndian.Uint16(data[5:7]))
	bodyEnd := headerLength + length

	if bodyEnd > len(data) {
		return BaseMessage{}, errors.New("Declared length exceeds actual data size")
	}

	payload := data[headerLength:bodyEnd]
	sig := data[bodyEnd : bodyEnd+32]

	base := BaseMessage{
		ID:      id,
		Type:    typ,
		Length:  uint16(length),
		Payload: payload,
		Sig:     sig,
	}
	return base, nil
}

func parseHelloMessage(data []byte) (HelloMessage, error) {

	baseMessage, err := parseMessage(data)

	if err != nil {
		return HelloMessage{}, err
	}

	if baseMessage.Type != Hello && baseMessage.Type != HelloReply {
		if baseMessage.Type == Error {
			return HelloMessage{}, errors.New("Error message received: " + string(baseMessage.Payload))
		}
		return HelloMessage{}, errors.New("Wrong message type. Expected Hello or HelloReply got" + string(baseMessage.Type))
	}
	// 4 bytes for extensions and at least 1 byte for name
	if len(baseMessage.Payload) < 5 {
		return HelloMessage{}, errors.New("Payload too short for Hello messages")
	}

	helloMessage := HelloMessage{
		BaseMessage: baseMessage,
		Extensions:  baseMessage.Payload[0:4],
		Name:        baseMessage.Payload[4:],
	}
	return helloMessage, nil
}

func createMessage(id uint32, typ MessageType, payload []byte) []byte {
	header := make([]byte, 7)
	binary.BigEndian.PutUint32(header[0:4], id)
	header[4] = byte(typ)

	length := uint16(len(payload))
	binary.BigEndian.PutUint16(header[5:7], length)

	message := make([]byte, 0)
	message = append(message, header...)
	message = append(message, payload...)

	return message
}

func createHelloMessage(id uint32, typ MessageType, extensions []byte, name []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {

	payload := make([]byte, 0)
	payload = append(payload, extensions...)
	payload = append(payload, name...)

	message := createMessage(id, typ, payload)

	sig, err := computeSignature(message, privateKey)
	if err != nil {
		return nil, err
	}
	message = append(message, sig...)

	return message, nil
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
