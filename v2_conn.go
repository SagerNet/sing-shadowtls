package shadowtls

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type shadowConn struct {
	net.Conn
	writer        N.VectorisedWriter
	readRemaining int
}

func newConn(conn net.Conn) *shadowConn {
	return &shadowConn{
		Conn:   conn,
		writer: bufio.NewVectorisedWriter(conn),
	}
}

func (c *shadowConn) Read(p []byte) (n int, err error) {
	if c.readRemaining > 0 {
		if len(p) > c.readRemaining {
			p = p[:c.readRemaining]
		}
		n, err = c.Conn.Read(p)
		c.readRemaining -= n
		return
	}
	var tlsHeader [5]byte
	_, err = io.ReadFull(c.Conn, tlsHeader[:])
	if err != nil {
		return
	}
	length := int(binary.BigEndian.Uint16(tlsHeader[3:5]))
	if tlsHeader[0] != 23 {
		return 0, E.New("unexpected TLS record type: ", tlsHeader[0])
	}
	readLen := len(p)
	if readLen > length {
		readLen = length
	}
	n, err = c.Conn.Read(p[:readLen])
	if err != nil {
		return
	}
	c.readRemaining = length - n
	return
}

func (c *shadowConn) Write(p []byte) (n int, err error) {
	err = c.WriteVectorised([]*buf.Buffer{buf.As(p)})
	if err == nil {
		n = len(p)
	}
	return
}

func (c *shadowConn) WriteVectorised(buffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(buffers)
	records := splitRecords(buffers, tlsHeaderSize, func(header []byte, payloadLen int, _ [][]byte) {
		header[0] = applicationData
		binary.BigEndian.PutUint16(header[1:3], tls.VersionTLS12)
		binary.BigEndian.PutUint16(header[3:5], uint16(payloadLen))
	})
	if len(records) == 0 {
		return nil
	}
	return common.Error(bufio.WriteVectorised(c.writer, records))
}

func (c *shadowConn) WriterMTU() int {
	return tlsMaxPlaintextSize
}

func (c *shadowConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *shadowConn) Upstream() any {
	return c.Conn
}

var (
	_ N.VectorisedWriter  = (*shadowConn)(nil)
	_ N.WriterWithMTU     = (*shadowConn)(nil)
	_ common.WithUpstream = (*shadowConn)(nil)
)
