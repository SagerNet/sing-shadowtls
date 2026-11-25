package shadowtls

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"hash"
	"io"
	"net"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/crypto/cryptobyte"
)

func extractFrame(conn net.Conn) (*buf.Buffer, error) {
	var tlsHeader [tlsHeaderSize]byte
	_, err := io.ReadFull(conn, tlsHeader[:])
	if err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(tlsHeader[3:]))
	buffer := buf.NewSize(tlsHeaderSize + length)
	common.Must1(buffer.Write(tlsHeader[:]))
	_, err = buffer.ReadFullFrom(conn, length)
	if err != nil {
		buffer.Release()
	}
	return buffer, err
}

func extractServerName(frame []byte) (string, error) {
	var hello *tls.ClientHelloInfo
	err := tls.Server(bufio.NewReadOnlyConn(bytes.NewReader(frame)), &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = argHello
			return nil, nil
		},
	}).HandshakeContext(context.Background())
	if hello != nil {
		return hello.ServerName, nil
	}
	return "", err
}

func verifyClientHello(frame []byte, users []User) (*User, error) {
	const minLen = tlsHeaderSize + 1 + 3 + 2 + tlsRandomSize + 1 + tlsSessionIDSize
	const hmacIndex = sessionIDLengthIndex + 1 + tlsSessionIDSize - hmacSize
	if len(frame) < minLen {
		return nil, io.ErrUnexpectedEOF
	} else if frame[0] != handshake {
		return nil, E.New("unexpected record type")
	} else if frame[5] != clientHello {
		return nil, E.New("unexpected handshake type")
	} else if frame[sessionIDLengthIndex] != tlsSessionIDSize {
		return nil, E.New("unexpected session id length")
	}
	for _, user := range users {
		hmacSHA1Hash := hmac.New(sha1.New, []byte(user.Password))
		hmacSHA1Hash.Write(frame[tlsHeaderSize:hmacIndex])
		hmacSHA1Hash.Write([]byte{0, 0, 0, 0})
		hmacSHA1Hash.Write(frame[hmacIndex+hmacSize:])
		if hmac.Equal(frame[hmacIndex:hmacIndex+hmacSize], hmacSHA1Hash.Sum(nil)[:hmacSize]) {
			return &user, nil
		}
	}
	return nil, E.New("hmac mismatch")
}

func parseServerHello(frame []byte) (serverRandom []byte, supportTLS13 bool) {
	var (
		input         = cryptobyte.String(frame)
		recordType    uint8
		record        cryptobyte.String
		messageType   uint8
		messageLength uint32
		sessionID     cryptobyte.String
		extensions    cryptobyte.String
	)
	if !input.ReadUint8(&recordType) || recordType != handshake ||
		!input.Skip(2) || !input.ReadUint16LengthPrefixed(&record) ||
		!record.ReadUint8(&messageType) || messageType != serverHello ||
		!record.ReadUint24(&messageLength) {
		return nil, false
	}
	message := record[:min(len(record), int(messageLength))]
	serverRandom = make([]byte, tlsRandomSize)
	if !message.Skip(2) || !message.CopyBytes(serverRandom) {
		return nil, false
	}
	if !message.ReadUint8LengthPrefixed(&sessionID) || !message.Skip(3) || !message.ReadUint16LengthPrefixed(&extensions) {
		return
	}
	for !extensions.Empty() {
		var (
			extensionType uint16
			extensionData cryptobyte.String
		)
		if !extensions.ReadUint16(&extensionType) || !extensions.ReadUint16LengthPrefixed(&extensionData) {
			return
		}
		if extensionType == extensionSupportedVersions {
			var selectedVersion uint16
			supportTLS13 = extensionData.ReadUint16(&selectedVersion) && extensionData.Empty() && selectedVersion == tls.VersionTLS13
			return
		}
	}
	return
}

func copyByFrameUntilHMACMatches(conn net.Conn, handshakeConn net.Conn, hmacVerify hash.Hash, hmacReset func()) (*buf.Buffer, error) {
	for {
		frameBuffer, err := extractFrame(conn)
		if err != nil {
			return nil, E.Cause(err, "read client record")
		}
		frame := frameBuffer.Bytes()
		if len(frame) > tlsHmacHeaderSize && frame[0] == applicationData {
			hmacReset()
			hmacVerify.Write(frame[tlsHmacHeaderSize:])
			hmacHash := hmacVerify.Sum(nil)[:4]
			if bytes.Equal(hmacHash, frame[tlsHeaderSize:tlsHmacHeaderSize]) {
				hmacReset()
				hmacVerify.Write(frame[tlsHmacHeaderSize:])
				hmacVerify.Write(frame[tlsHeaderSize:tlsHmacHeaderSize])
				frameBuffer.Advance(tlsHmacHeaderSize)
				return frameBuffer, nil
			}
		}
		_, err = handshakeConn.Write(frame)
		frameBuffer.Release()
		if err != nil {
			return nil, E.Cause(err, "write clint frame")
		}
	}
}

func copyByFrameWithModification(conn net.Conn, handshakeConn net.Conn, password string, serverRandom []byte, hmacWrite hash.Hash) error {
	writeKey := kdf(password, serverRandom)
	writer := bufio.NewExtendedWriter(handshakeConn)
	frontHeadroom := N.CalculateFrontHeadroom(handshakeConn)
	rearHeadroom := N.CalculateRearHeadroom(handshakeConn)
	for {
		frameBuffer, err := extractFrame(conn)
		if err != nil {
			return E.Cause(err, "read server record")
		}
		frame := frameBuffer.Bytes()
		if frame[0] == applicationData {
			xorSlice(frame[tlsHeaderSize:], writeKey)
			hmacWrite.Write(frame[tlsHeaderSize:])
			binary.BigEndian.PutUint16(frame[3:], uint16(len(frame)-tlsHeaderSize+hmacSize))
			record := buf.NewSize(frontHeadroom + len(frame) + hmacSize + rearHeadroom)
			record.Resize(frontHeadroom, 0)
			common.Must1(record.Write(frame[:tlsHeaderSize]))
			common.Must1(record.Write(hmacWrite.Sum(nil)[:hmacSize]))
			common.Must1(record.Write(frame[tlsHeaderSize:]))
			frameBuffer.Release()
			err = writer.WriteBuffer(record)
			if err != nil {
				return E.Cause(err, "write modified server frame")
			}
		} else {
			_, err = handshakeConn.Write(frame)
			frameBuffer.Release()
			if err != nil {
				return E.Cause(err, "write server frame")
			}
		}
	}
}
