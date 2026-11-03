package shadowtls

import (
	std_bufio "bufio"
	"crypto/hmac"
	"crypto/sha1"
	"hash"
	"io"
	"net"
	"sync"
)

type hashReadConn struct {
	net.Conn
	reader *std_bufio.Reader
	hmac   hash.Hash
}

func newHashReadConn(conn net.Conn, password string) *hashReadConn {
	readHMAC := hmac.New(sha1.New, []byte(password))
	return &hashReadConn{
		Conn:   conn,
		reader: std_bufio.NewReaderSize(io.TeeReader(conn, readHMAC), 16*1024),
		hmac:   readHMAC,
	}
}

func (c *hashReadConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *hashReadConn) Sum() []byte {
	return c.hmac.Sum(nil)[:8]
}

type hashWriteConn struct {
	net.Conn
	access     sync.Mutex
	hmac       hash.Hash
	hasContent bool
	lastSum    []byte
}

func newHashWriteConn(conn net.Conn, password string) *hashWriteConn {
	return &hashWriteConn{
		Conn: conn,
		hmac: hmac.New(sha1.New, []byte(password)),
	}
}

func (c *hashWriteConn) Write(p []byte) (n int, err error) {
	c.access.Lock()
	if c.hmac != nil {
		if c.hasContent {
			c.lastSum = c.hmac.Sum(nil)[:8]
		}
		c.hmac.Write(p)
		c.hasContent = true
	}
	c.access.Unlock()
	return c.Conn.Write(p)
}

func (c *hashWriteConn) Sums() (current []byte, last []byte, hasContent bool) {
	c.access.Lock()
	defer c.access.Unlock()
	if !c.hasContent || c.hmac == nil {
		return
	}
	return c.hmac.Sum(nil)[:8], c.lastSum, true
}

func (c *hashWriteConn) Fallback() {
	c.access.Lock()
	defer c.access.Unlock()
	c.hmac = nil
}
