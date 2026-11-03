package shadowtls

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"hash"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type verifiedConn struct {
	net.Conn
	writer           N.ExtendedWriter
	vectorisedWriter N.VectorisedWriter
	access           sync.Mutex
	hmacAdd          hash.Hash
	hmacVerify       hash.Hash
	hmacIgnore       hash.Hash
	buffer           *buf.Buffer
}

func newVerifiedConn(
	conn net.Conn,
	hmacAdd hash.Hash,
	hmacVerify hash.Hash,
	hmacIgnore hash.Hash,
) *verifiedConn {
	return &verifiedConn{
		Conn:             conn,
		writer:           bufio.NewExtendedWriter(conn),
		vectorisedWriter: bufio.NewVectorisedWriter(conn),
		hmacAdd:          hmacAdd,
		hmacVerify:       hmacVerify,
		hmacIgnore:       hmacIgnore,
	}
}

func (c *verifiedConn) Read(b []byte) (n int, err error) {
	if c.buffer != nil {
		if !c.buffer.IsEmpty() {
			return c.buffer.Read(b)
		}
		c.buffer.Release()
		c.buffer = nil
	}
	for {
		var tlsHeader [tlsHeaderSize]byte
		_, err = io.ReadFull(c.Conn, tlsHeader[:])
		if err != nil {
			sendAlert(c.Conn)
			return
		}
		length := int(binary.BigEndian.Uint16(tlsHeader[3:tlsHeaderSize]))
		c.buffer = buf.NewSize(tlsHeaderSize + length)
		common.Must1(c.buffer.Write(tlsHeader[:]))
		_, err = c.buffer.ReadFullFrom(c.Conn, length)
		if err != nil {
			return
		}
		buffer := c.buffer.Bytes()
		switch buffer[0] {
		case alert:
			err = E.Cause(net.ErrClosed, "remote alert")
			return
		case applicationData:
			if c.hmacIgnore != nil {
				if verifyApplicationData(buffer, c.hmacIgnore, false) {
					c.buffer.Release()
					c.buffer = nil
					continue
				} else {
					c.hmacIgnore = nil
				}
			}
			if !verifyApplicationData(buffer, c.hmacVerify, true) {
				sendAlert(c.Conn)
				err = E.New("application data verification failed")
				return
			}
			c.buffer.Advance(tlsHmacHeaderSize)
		default:
			sendAlert(c.Conn)
			err = E.New("unexpected TLS record type: ", buffer[0])
			return
		}
		return c.buffer.Read(b)
	}
}

func (c *verifiedConn) Write(p []byte) (n int, err error) {
	err = c.WriteVectorised([]*buf.Buffer{buf.As(p)})
	if err == nil {
		n = len(p)
	}
	return
}

func (c *verifiedConn) WriteBuffer(buffer *buf.Buffer) error {
	if buffer.Len() > tlsMaxPlaintextSize {
		return c.WriteVectorised([]*buf.Buffer{buffer})
	}
	c.access.Lock()
	defer c.access.Unlock()
	payload := buffer.Bytes()
	c.putHeaderLocked(buffer.ExtendHeader(tlsHmacHeaderSize), len(payload), [][]byte{payload})
	return c.writer.WriteBuffer(buffer)
}

func (c *verifiedConn) WriteVectorised(buffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(buffers)
	c.access.Lock()
	defer c.access.Unlock()
	records := splitRecords(buffers, tlsHmacHeaderSize, c.putHeaderLocked)
	if len(records) == 0 {
		return nil
	}
	return common.Error(bufio.WriteVectorised(c.vectorisedWriter, records))
}

func (c *verifiedConn) putHeaderLocked(header []byte, payloadLen int, payload [][]byte) {
	header[0] = applicationData
	header[1] = 3
	header[2] = 3
	binary.BigEndian.PutUint16(header[3:tlsHeaderSize], uint16(hmacSize+payloadLen))
	for _, segment := range payload {
		c.hmacAdd.Write(segment)
	}
	hmacHash := c.hmacAdd.Sum(nil)[:hmacSize]
	c.hmacAdd.Write(hmacHash)
	copy(header[tlsHeaderSize:], hmacHash)
}

func (c *verifiedConn) FrontHeadroom() int {
	return tlsHmacHeaderSize
}

func (c *verifiedConn) WriterMTU() int {
	return tlsMaxPlaintextSize
}

func (c *verifiedConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *verifiedConn) Upstream() any {
	return c.Conn
}

func verifyApplicationData(frame []byte, hmac hash.Hash, update bool) bool {
	if frame[1] != 3 || frame[2] != 3 || len(frame) < tlsHmacHeaderSize {
		return false
	}
	hmac.Write(frame[tlsHmacHeaderSize:])
	hmacHash := hmac.Sum(nil)[:hmacSize]
	if update {
		hmac.Write(hmacHash)
	}
	return bytes.Equal(frame[tlsHeaderSize:tlsHeaderSize+hmacSize], hmacHash)
}

func splitRecords(buffers []*buf.Buffer, headerSize int, putHeader func(header []byte, payloadLen int, payload [][]byte)) [][]byte {
	totalLen := buf.LenMulti(buffers)
	if totalLen == 0 {
		return nil
	}
	headers := make([]byte, (totalLen+tlsMaxPlaintextSize-1)/tlsMaxPlaintextSize*headerSize)
	var (
		records     [][]byte
		recordIndex int
		recordLen   int
	)
	for _, buffer := range buffers {
		for data := buffer.Bytes(); len(data) > 0; {
			if recordLen == 0 {
				recordIndex = len(records)
				records = append(records, headers[:headerSize])
				headers = headers[headerSize:]
			}
			segment := data
			if len(segment) > tlsMaxPlaintextSize-recordLen {
				segment = segment[:tlsMaxPlaintextSize-recordLen]
			}
			data = data[len(segment):]
			records = append(records, segment)
			recordLen += len(segment)
			if recordLen == tlsMaxPlaintextSize {
				putHeader(records[recordIndex], recordLen, records[recordIndex+1:])
				recordLen = 0
			}
		}
	}
	if recordLen > 0 {
		putHeader(records[recordIndex], recordLen, records[recordIndex+1:])
	}
	return records
}

func sendAlert(writer io.Writer) {
	const recordSize = 31
	record := [recordSize]byte{
		alert,
		3,
		3,
		0,
		recordSize - tlsHeaderSize,
	}
	_, err := rand.Read(record[tlsHeaderSize:])
	if err != nil {
		return
	}
	writer.Write(record[:])
}

var (
	_ N.ExtendedWriter    = (*verifiedConn)(nil)
	_ N.VectorisedWriter  = (*verifiedConn)(nil)
	_ N.FrontHeadroom     = (*verifiedConn)(nil)
	_ N.WriterWithMTU     = (*verifiedConn)(nil)
	_ common.WithUpstream = (*verifiedConn)(nil)
)
