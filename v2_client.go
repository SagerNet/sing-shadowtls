package shadowtls

import (
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

type clientConn struct {
	*shadowConn
	hashConn *hashReadConn
}

func newClientConn(hashConn *hashReadConn) *clientConn {
	return &clientConn{newConn(hashConn.Conn), hashConn}
}

func (c *clientConn) Write(p []byte) (n int, err error) {
	if c.hashConn != nil {
		sum := c.hashConn.Sum()
		c.hashConn = nil
		_, err = bufio.WriteVectorised(c.shadowConn, [][]byte{sum, p})
		if err == nil {
			n = len(p)
		}
		return
	}
	return c.shadowConn.Write(p)
}

func (c *clientConn) WriteBuffer(buffer *buf.Buffer) error {
	if c.hashConn != nil {
		return c.WriteVectorised([]*buf.Buffer{buffer})
	}
	return c.shadowConn.WriteBuffer(buffer)
}

func (c *clientConn) WriteVectorised(buffers []*buf.Buffer) error {
	if c.hashConn != nil {
		sum := c.hashConn.Sum()
		c.hashConn = nil
		return c.shadowConn.WriteVectorised(append([]*buf.Buffer{buf.As(sum)}, buffers...))
	}
	return c.shadowConn.WriteVectorised(buffers)
}

var (
	_ N.ExtendedWriter   = (*clientConn)(nil)
	_ N.VectorisedWriter = (*clientConn)(nil)
)
