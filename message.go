package main

import (
	"crypto/ed25519"
	"encoding/base32"
	"strconv"
	"strings"
)

type Message struct {
	Header Header
	Body   []string
	Footer string
}

// String returns a serialized Message string
func (m Message) String() string {
	var sb strings.Builder

	sb.WriteString(m.unsignedString())
	sb.WriteString(signature + " " + m.Footer + "\n\n")
	return sb.String()
}

func (m Message) unsignedString() string {
	var sb strings.Builder

	sb.WriteString(author + " " + m.Header.author + "\n")
	sb.WriteString(depth + " " + strconv.Itoa(m.Header.depth) + "\n")
	sb.WriteString(kind + " " + m.Header.kind + "\n")
	sb.WriteString(prev + " " + m.Header.prev + "\n\n")

	for _, line := range m.Body {
		sb.WriteString(line + "\n")
	}

	sb.WriteString("\n")
	return sb.String()
}

// IsValid verifies the message footer (signature) and returns true if it is valid
func (m Message) IsValid() (bool, error) {
	a := strings.TrimPrefix(m.Header.author, authorPrefix)
	pubKey, err := base32.NewEncoding(crockford).WithPadding(base32.NoPadding).DecodeString(a)
	if err != nil {
		return false, err
	}
	sig, err := base32.NewEncoding(crockford).WithPadding(base32.NoPadding).DecodeString(m.Footer)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(pubKey, []byte(m.unsignedString()), sig), err
}
