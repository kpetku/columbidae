package main

import (
	"bufio"
	"io"
	"regexp"
	"strconv"
	"strings"
)

type MessageReader struct {
	r       io.Reader
	scanner *bufio.Scanner
	err     error

	state   state
	Message Message
}

// NewMessageReader returns a new MessageReader so the underlying Message from a reader can be accessed in struct form as mr.Message after calling Read()
func NewMessageReader(r io.Reader) MessageReader {
	scanner := bufio.NewScanner(r)
	mr := MessageReader{}
	msg := Message{}
	mr.Message = msg
	mr.r = r
	mr.scanner = scanner
	mr.state = ReadHeaderAuthor
	return mr
}

// Read actually reads a MessageReader into mr.Message
func (mr *MessageReader) Read() (err error) {
	for stateTest := 0; stateTest < int(InvalidMessage); stateTest++ {
		if mr.state != ReadHeaderEOF {
			mr.scanner.Scan()
		}
		err = mr.next()
		if err != nil || mr.err != nil {
			return err
		}
		mr.state++
	}
	return nil
}

func (mr *MessageReader) next() (err error) {
	switch mr.state {
	case ReadHeaderAuthor:
		mr.Message.Header.author, mr.err = mr.readString(author)
	case ReadHeaderDepth:
		mr.Message.Header.depth, mr.err = mr.readInt(depth)
	case ReadHeaderKind:
		mr.Message.Header.kind, mr.err = mr.readString(kind)
	case ReadHeaderPrev:
		mr.Message.Header.prev, mr.err = mr.readString(prev)
	case ReadHeaderEOF:
	case ReadBodies:
		mr.Message.Body, mr.err = mr.readBodies()
	case ReadBodyEOF:
	case ReadMessageFooter:
		mr.Message.Footer, mr.err = mr.readString(signature)
	case VerifyMessageSignature:
		mr.err = mr.verifyMessageSignature()
	}
	return mr.err
}

func (mr *MessageReader) readString(s string) (result string, err error) {
	if !strings.HasPrefix(mr.scanner.Text(), s) {
		mr.state = InvalidMessage
		return "", errMalformedLine
	}
	split := strings.Fields(mr.scanner.Text())
	err = checkLine(s, split)
	return split[1], err
}

func (mr *MessageReader) readInt(s string) (result int, err error) {
	tmp, err := mr.readString(s)
	mr.err = err
	return strconv.Atoi(tmp)
}

func (mr *MessageReader) readBodies() (bodies []string, err error) {
	var counter int
	var line string
	for mr.scanner.Scan() {
		if mr.scanner.Text() == "" {
			mr.Message.Body = bodies
			mr.state++
			break
		}
		if !strings.ContainsAny(mr.scanner.Text(), ":") && mr.scanner.Text() != "NONE" {
			return nil, errMalformedBody
		}
		counter++
		if counter >= maxValueLen {
			err = errInvalidBodyLength
			return nil, err
		}
		line = mr.scanner.Text()
		if err = checkBodyValue(line); err != nil {
			mr.err = err
			return nil, err
		}
		bodies = append(bodies, line)
	}
	return bodies, err
}

func (mr *MessageReader) verifyMessageSignature() (err error) {
	valid, err := mr.Message.IsValid()
	if err != nil {
		return err
	}
	if !valid {
		return errInvalidSig
	}
	return err
}

func checkLine(key string, line []string) (err error) {
	if len(line) < 1 {
		err = errMalformedLine
		return
	}
	if line[0] == key && len(line) == 2 {
		if key == kind {
			err = validateKind(line[1])
		}
		if len(line[1]) > maxValueLen {
			err = errInvalidBodyLength
		}
		return err
	}
	return errMalformedLine
}

func checkBodyValue(line string) error {
	if len(line) > maxValueLen || hasMultihashPrefix(line) {
		return errInvalidBodyLength
	}
	return nil
}

func hasMultihashPrefix(line string) bool {
	// TODO: Check length of multihash lines
	if strings.HasPrefix(line, "USER.") || strings.HasPrefix(line, "TEXT.") || strings.HasPrefix(line, "FILE.") {
		return true
	}
	return false
}

func validateKind(line string) error {
	if len(line) > maxKeyLen {
		return errMalformedHeader
	}
	matched, err := regexp.MatchString(`^[A-Z|a-z|\-|\_|\.|0-9]{1,90}$`, line)
	if matched || err != nil {
		return err
	}
	return errMalformedHeader
}
