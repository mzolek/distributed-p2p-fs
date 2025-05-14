package main

import (
	"bytes"
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

func printMessage(message BaseMessage) {
	fmt.Println("-------------------------------")
	fmt.Println("ID: ", message.ID)
	fmt.Println("Type: ", message.Type)
	fmt.Println("Length: ", message.Length)
	fmt.Println("Payload: ", string(message.Payload))
	// fmt.Println("Sig: ", message.Sig)
	fmt.Println("-------------------------------")
}

func parseMessage(data []byte) (BaseMessage, error) {
	if len(data) < 7 {
		return BaseMessage{}, errors.New("data too short")
	}

	id := binary.BigEndian.Uint32(data[0:4])
	typ := MessageType(data[4])
	length := binary.BigEndian.Uint16(data[5:7])
	bodyEnd := 7 + length

	if int(bodyEnd) > len(data) {
		return BaseMessage{}, errors.New("declared length exceeds actual data size")
	}

	payload := data[7:bodyEnd]
	sig := data[bodyEnd:]

	base := BaseMessage{
		ID:      id,
		Type:    typ,
		Length:  length,
		Payload: payload,
		Sig:     sig,
	}
	return base, nil
}

func parseHelloMessage(data []byte) (HelloMessage, error) {

	baseMessage, err := parseMessage(data)
	failOnErr(err)

	if baseMessage.Type != Hello && baseMessage.Type != HelloReply {
		return HelloMessage{
			BaseMessage: baseMessage,
			Name:        nil,
			Extensions:  nil,
		}, errors.New("Expected Hello or HelloReply message type")
	}

	if len(baseMessage.Payload) < 4 {
		return HelloMessage{
			BaseMessage: baseMessage,
			Name:        nil,
			Extensions:  nil,
		}, errors.New("payload too short for HelloMessage")
	}

	fmt.Println("baseMessage: ", baseMessage)

	helloMessage := HelloMessage{
		BaseMessage: baseMessage,
		Extensions:  baseMessage.Payload[0:4],
		Name:        baseMessage.Payload[4:],
	}

	return helloMessage, nil
}

func createHelloMessage(id uint32, typ MessageType, extensions []byte, name []byte, privateKey *ecdsa.PrivateKey) []byte {

	payload := make([]byte, 0)

	header := make([]byte, 7)
	binary.BigEndian.PutUint32(header[0:4], id)
	header[4] = byte(typ)

	length := uint16(len(extensions) + len(name))
	binary.BigEndian.PutUint16(header[5:7], length)

	payload = append(payload, header...)

	payload = append(payload, extensions...)
	payload = append(payload, name...)
	fmt.Println("payload: ", payload)

	// payload = append(payload, sig...)
	sig, err := computeSignature(payload, privateKey)
	failOnErr(err)
	payload = append(payload, sig...)
	// fmt.Println("sig: ", len(sig))
	return payload
}

func validateMessage(id uint32, sig []byte, message BaseMessage) error {
	if id != message.ID || !bytes.Equal(sig, message.Sig) {
		return errors.New("Not a valid message")
	}
	return nil
}

func computeSignature(data []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hashed := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature, err
}

func verifySignature(publicKey *ecdsa.PublicKey, data []byte, signature []byte) bool {
	var r, s big.Int
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])
	hashed := sha256.Sum256(data)
	return ecdsa.Verify(publicKey, hashed[:], &r, &s)
}
