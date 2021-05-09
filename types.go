package main

import "errors"

const (
	author    = "author"
	depth     = "depth"
	kind      = "kind"
	prev      = "prev"
	signature = "signature"
)

const maxKeyLen = 90
const maxValueLen = 128

const authorPrefix = "USER."

var (
	errMalformedLine     = errors.New("malformed line")
	errMalformedHeader   = errors.New("malformed header")
	errMalformedBody     = errors.New("malformed body")
	errInvalidBodyLength = errors.New("invalid body length")
	errInvalidSig        = errors.New("invalid signature for message")
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

type state int

const (
	ReadHeaderAuthor state = iota
	ReadHeaderDepth
	ReadHeaderKind
	ReadHeaderPrev
	ReadHeaderEOF
	ReadBodies
	ReadBodyEOF
	ReadMessageFooter
	ReadFooterEOF
	VerifyMessageSignature
	InvalidMessage
)

type Header struct {
	author string
	depth  int
	kind   string
	prev   string
}
