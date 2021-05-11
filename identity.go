package main

import (
	"crypto/ed25519"
	"encoding/base32"
	"encoding/base64"
)

type Identity struct {
	Name    string
	PubKey  ed25519.PublicKey
	PrivKey ed25519.PrivateKey
}

// NewIdentity creates a new identity PubKey and PrivKey keypair to use for signing messages
func NewIdentity() (Identity, error) {
	i := Identity{}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return Identity{}, err
	}
	data := base32.NewEncoding(crockford).WithPadding(base32.NoPadding).EncodeToString(pub)
	i.Name = authorPrefix + data
	i.PubKey = pub
	i.PrivKey = priv

	return i, nil
}

// GetPrivKey returns a stanard base64 encoded string of an Identity PrivKey
func (i Identity) GetPrivKey() string {
	return base64.StdEncoding.EncodeToString(i.PrivKey)
}

// GetPrivKey returns a crockford base32 encoded string of an Identity PubKey
func (i Identity) GetPubKey() string {
	return base32.NewEncoding(crockford).WithPadding(base32.NoPadding).EncodeToString(i.PubKey)
}
