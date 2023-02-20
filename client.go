package shadowtls

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"net"
	"os"

	"github.com/sagernet/sing/common/debug"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type ClientConfig struct {
	Version      int
	Password     string
	Server       M.Socksaddr
	Dialer       N.Dialer
	TLSHandshake TLSHandshakeFunc
	Logger       logger.ContextLogger
}

type Client struct {
	version      int
	password     string
	server       M.Socksaddr
	dialer       N.Dialer
	tlsHandshake TLSHandshakeFunc
	logger       logger.ContextLogger
}

func NewClient(config ClientConfig) (*Client, error) {
	client := &Client{
		version:      config.Version,
		password:     config.Password,
		server:       config.Server,
		dialer:       config.Dialer,
		tlsHandshake: config.TLSHandshake,
		logger:       config.Logger,
	}
	if !client.server.IsValid() || client.dialer == nil || client.tlsHandshake == nil {
		return nil, os.ErrInvalid
	}
	switch client.version {
	case 1, 2, 3:
	default:
		return nil, E.New("unknown protocol version: ", client.version)
	}
	if client.dialer == nil {
		client.dialer = N.SystemDialer
	}
	return client, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	conn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.server)
	if err != nil {
		return nil, err
	}
	switch c.version {
	default:
		fallthrough
	case 1:
		err = c.tlsHandshake(ctx, conn, nil)
		if err != nil {
			return nil, err
		}
		c.logger.TraceContext(ctx, "clint handshake finished")
		return conn, nil
	case 2:
		hashConn := newHashReadConn(conn, c.password)
		err = c.tlsHandshake(ctx, hashConn, nil)
		if err != nil {
			return nil, err
		}
		c.logger.TraceContext(ctx, "clint handshake finished")
		return newClientConn(hashConn), nil
	case 3:
		stream := newStreamWrapper(conn, c.password)
		err = c.tlsHandshake(ctx, stream, generateSessionID(c.password))
		if err != nil {
			return nil, err
		}
		c.logger.TraceContext(ctx, "handshake success")
		authorized, serverRandom, readHMAC := stream.Authorized()
		if !authorized {
			return nil, E.New("traffic hijacked or TLS1.3 is not supported")
		}
		if debug.Enabled {
			c.logger.TraceContext(ctx, "authorized, server random extracted: ", hex.EncodeToString(serverRandom))
		}
		hmacAdd := hmac.New(sha1.New, []byte(c.password))
		hmacAdd.Write(serverRandom)
		hmacAdd.Write([]byte("C"))
		hmacVerify := hmac.New(sha1.New, []byte(c.password))
		hmacVerify.Write(serverRandom)
		hmacVerify.Write([]byte("S"))
		return newVerifiedConn(conn, hmacAdd, hmacVerify, readHMAC), nil
	}
}
