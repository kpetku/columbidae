package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
)

type Identity struct {
	Name    string
	PubKey  ed25519.PublicKey
	PrivKey ed25519.PrivateKey
}

func NewIdentity() (*Identity, error) {
	i := new(Identity)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return &Identity{}, err
	}
	data := base32.NewEncoding(crockford).WithPadding(base32.NoPadding).EncodeToString(pub)
	i.Name = authorPrefix + data
	i.PubKey = pub
	i.PrivKey = priv

	return i, nil
}

func (i *Identity) NewMessage(depth int, kind string, prev string, content []string) (*Message, error) {
	m := Message{}
	m.Header.author = i.Name
	m.Header.depth = depth
	m.Header.prev = prev
	m.Header.kind = kind
	m.Body = content

	sig, err := i.PrivKey.Sign(rand.Reader, []byte(m.String()), crypto.Hash(0))
	if err != nil {
		return &Message{}, err
	}
	data := base32.NewEncoding(crockford).WithPadding(base32.NoPadding).EncodeToString(sig)

	m.Footer = data
	return &m, nil
}
