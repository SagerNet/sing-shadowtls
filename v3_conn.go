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
	err = c.WriteBuffer(buf.As(p))
	if err == nil {
		n = len(p)
	}
	return
}

func (c *verifiedConn) WriteBuffer(buffer *buf.Buffer) error {
	if buffer.IsEmpty() || buffer.Len() > tlsMaxPlaintextSize {
		return c.writeRecords([]*buf.Buffer{buffer})
	}
	buffer = ensureHeadroom(buffer, tlsHmacHeaderSize+N.CalculateFrontHeadroom(c.Conn), N.CalculateRearHeadroom(c.Conn))
	c.access.Lock()
	defer c.access.Unlock()
	payload := buffer.Bytes()
	c.putHeaderLocked(buffer.ExtendHeader(tlsHmacHeaderSize), payload)
	return c.writer.WriteBuffer(buffer)
}

func (c *verifiedConn) WriteVectorised(buffers []*buf.Buffer) error {
	if len(buffers) == 1 {
		return c.WriteBuffer(buffers[0])
	}
	return c.writeRecords(buffers)
}

func (c *verifiedConn) writeRecords(buffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(buffers)
	c.access.Lock()
	defer c.access.Unlock()
	records := newRecords(buffers, tlsHmacHeaderSize, N.CalculateFrontHeadroom(c.Conn), N.CalculateRearHeadroom(c.Conn), c.putHeaderLocked)
	if len(records) == 0 {
		return nil
	}
	return c.vectorisedWriter.WriteVectorised(records)
}

func (c *verifiedConn) putHeaderLocked(header []byte, payload []byte) {
	header[0] = applicationData
	header[1] = 3
	header[2] = 3
	binary.BigEndian.PutUint16(header[3:tlsHeaderSize], uint16(hmacSize+len(payload)))
	c.hmacAdd.Write(payload)
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

func newRecords(buffers []*buf.Buffer, headerSize int, frontHeadroom int, rearHeadroom int, putHeader func(header []byte, payload []byte)) []*buf.Buffer {
	remaining := buf.LenMulti(buffers)
	records := make([]*buf.Buffer, 0, (remaining+tlsMaxPlaintextSize-1)/tlsMaxPlaintextSize)
	var record *buf.Buffer
	for _, buffer := range buffers {
		data := buffer.Bytes()
		for len(data) > 0 {
			if record == nil {
				recordLen := remaining
				if recordLen > tlsMaxPlaintextSize {
					recordLen = tlsMaxPlaintextSize
				}
				remaining -= recordLen
				record = buf.NewSize(frontHeadroom + headerSize + recordLen + rearHeadroom)
				record.Resize(frontHeadroom+headerSize, 0)
				record.Reserve(rearHeadroom)
			}
			data = data[common.Must1(record.Write(data)):]
			if record.IsFull() {
				record.OverCap(rearHeadroom)
				payload := record.Bytes()
				putHeader(record.ExtendHeader(headerSize), payload)
				records = append(records, record)
				record = nil
			}
		}
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
