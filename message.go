package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strconv"
	"strings"
)

// Message contains the header, body, footer signature of a Message
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

// IsValid verifies if the message footer signature was signed by the Message Author
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

// Sign signs a Message with an Identity privateKey
func (m *Message) Sign(i Identity) error {
	if m.Footer != "" {
		return errors.New("unable to sign message: message already signed")
	}
	if i.PrivKey == nil {
		return errors.New("unable to sign message: invalid identity PrivKey")
	}
	sig, err := i.PrivKey.Sign(rand.Reader, []byte(m.unsignedString()), crypto.Hash(0))
	if err != nil {
		return err
	}
	data := base32.NewEncoding(crockford).WithPadding(base32.NoPadding).EncodeToString(sig)

	m.Footer = data
	return nil
}
