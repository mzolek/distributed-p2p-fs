package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
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

func parseMessage(data []byte) (BaseMessage, error) {
	if len(data) < 7 {
		return BaseMessage{}, errors.New("data too short")
	}

	id := binary.BigEndian.Uint32(data[0:4])
	typ := MessageType(data[4])
	length := binary.BigEndian.Uint16(data[5:7])
	fmt.Println("length: ", length)
	bodyEnd := 7 + length
	fmt.Println("bodyEnd: ", bodyEnd)

	if int(bodyEnd) > len(data) {
		return BaseMessage{}, errors.New("declared length exceeds actual data size")
	}

	payload := data[7:bodyEnd]
	sig := data[bodyEnd : bodyEnd+4]

	base := BaseMessage{
		ID:      id,
		Type:    typ,
		Length:  length,
		Payload: payload,
		Sig:     sig,
	}
	fmt.Println("base: ", base)
	return base, nil
}

func parseHelloMessage(data []byte) (HelloMessage, error) {

	baseMessage, err := parseMessage(data)
	failOnErr(err)

	if baseMessage.Type != Hello && baseMessage.Type != HelloReply {
		return HelloMessage{}, errors.New("Expected Hello or HelloReply message type")
	}

	if len(baseMessage.Payload) < 4 {
		return HelloMessage{}, errors.New("payload too short for HelloMessage")
	}

	fmt.Println("baseMessage: ", baseMessage)

	helloMessage := HelloMessage{
		BaseMessage: baseMessage,
		Extensions:  baseMessage.Payload[0:4],
		Name:        baseMessage.Payload[4:],
	}

	return helloMessage, nil
}

func createHelloMessage(id uint32, typ MessageType, extensions []byte, name []byte, sig []byte) []byte {

	payload := make([]byte, 0, 7+len(extensions)+len(name)+len(sig))

	header := make([]byte, 7)
	binary.BigEndian.PutUint32(header[0:4], id)
	header[4] = byte(typ)

	length := uint16(len(extensions) + len(name))
	binary.BigEndian.PutUint16(header[5:7], length)

	payload = append(payload, header...)
	payload = append(payload, extensions...)
	payload = append(payload, name...)
	payload = append(payload, sig...)

	return payload
}

func validateMessage(id uint32, sig []byte, message BaseMessage) error {
	if id != message.ID || !bytes.Equal(sig, message.Sig) {
		return errors.New("Not a valid message")
	}
	return nil
}
