package shadowtls

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"net"
	"os"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/debug"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/task"
)

type ServiceConfig struct {
	Version                int
	Password               string // for protocol version 2
	Users                  []User // for protocol version 3
	Handshake              HandshakeConfig
	HandshakeForServerName map[string]HandshakeConfig // for protocol version 2/3
	StrictMode             bool                       // for protocol version 3
	Handler                Handler
	Logger                 logger.ContextLogger
}

type User struct {
	Name     string
	Password string
}

type HandshakeConfig struct {
	Server M.Socksaddr
	Dialer N.Dialer
}

type Handler interface {
	N.TCPConnectionHandler
	E.Handler
}

type Service struct {
	version                int
	password               string
	users                  []User
	handshake              HandshakeConfig
	handshakeForServerName map[string]HandshakeConfig
	strictMode             bool
	handler                Handler
	logger                 logger.ContextLogger
}

func NewService(config ServiceConfig) (*Service, error) {
	service := &Service{
		version:                config.Version,
		password:               config.Password,
		users:                  config.Users,
		handshake:              config.Handshake,
		handshakeForServerName: config.HandshakeForServerName,
		strictMode:             config.StrictMode,
		handler:                config.Handler,
		logger:                 config.Logger,
	}

	if !service.handshake.Server.IsValid() {
		return nil, E.New("missing default handshake information")
	}

	if service.handler == nil || service.logger == nil {
		return nil, os.ErrInvalid
	}
	switch config.Version {
	case 1, 2:
	case 3:
		if len(service.users) == 0 {
			return nil, E.New("missing users")
		}
	default:
		return nil, E.New("unknown protocol version: ", config.Version)
	}

	return service, nil
}

func (s *Service) selectHandshake(clientHelloFrame *buf.Buffer) HandshakeConfig {
	serverName, err := extractServerName(clientHelloFrame.Bytes())
	if err == nil {
		if customHandshake, found := s.handshakeForServerName[serverName]; found {
			return customHandshake
		}
	}
	return s.handshake
}

func (s *Service) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	switch s.version {
	default:
		fallthrough
	case 1:
		handshakeConn, err := s.handshake.Dialer.DialContext(ctx, N.NetworkTCP, s.handshake.Server)
		if err != nil {
			return E.Cause(err, "server handshake")
		}

		var group task.Group
		group.Append("client handshake", func(ctx context.Context) error {
			return copyUntilHandshakeFinished(handshakeConn, conn)
		})
		group.Append("server handshake", func(ctx context.Context) error {
			return copyUntilHandshakeFinished(conn, handshakeConn)
		})
		group.FastFail()
		group.Cleanup(func() {
			handshakeConn.Close()
		})
		err = group.Run(ctx)
		if err != nil {
			return err
		}
		s.logger.TraceContext(ctx, "handshake finished")
		return s.handler.NewConnection(ctx, conn, metadata)
	case 2:
		clientHelloFrame, err := extractFrame(conn)
		if err != nil {
			return E.Cause(err, "read client handshake")
		}

		handshakeConfig := s.selectHandshake(clientHelloFrame)
		handshakeConn, err := handshakeConfig.Dialer.DialContext(ctx, N.NetworkTCP, handshakeConfig.Server)
		if err != nil {
			return E.Cause(err, "server handshake")
		}
		hashConn := newHashWriteConn(conn, s.password)
		go bufio.Copy(hashConn, handshakeConn)
		var request *buf.Buffer
		request, err = copyUntilHandshakeFinishedV2(ctx, s.logger, handshakeConn, bufio.NewCachedConn(conn, clientHelloFrame), hashConn, 2)
		if err == nil {
			s.logger.TraceContext(ctx, "handshake finished")
			handshakeConn.Close()
			return s.handler.NewConnection(ctx, bufio.NewCachedConn(newConn(conn), request), metadata)
		} else if err == os.ErrPermission {
			s.logger.WarnContext(ctx, "fallback connection")
			hashConn.Fallback()
			return common.Error(bufio.Copy(handshakeConn, conn))
		} else {
			return err
		}
	case 3:
		clientHelloFrame, err := extractFrame(conn)
		if err != nil {
			return E.Cause(err, "read client handshake")
		}

		handshakeConfig := s.selectHandshake(clientHelloFrame)
		handshakeConn, err := handshakeConfig.Dialer.DialContext(ctx, N.NetworkTCP, handshakeConfig.Server)
		if err != nil {
			return E.Cause(err, "server handshake")
		}

		_, err = handshakeConn.Write(clientHelloFrame.Bytes())
		if err != nil {
			clientHelloFrame.Release()
			return E.Cause(err, "write client handshake")
		}
		user, err := verifyClientHello(clientHelloFrame.Bytes(), s.users)
		if err != nil {
			s.logger.WarnContext(ctx, E.Cause(err, "client hello verify failed"))
			return bufio.CopyConn(ctx, conn, handshakeConn)
		}
		if user.Name != "" {
			ctx = auth.ContextWithUser(ctx, user.Name)
		}
		s.logger.TraceContext(ctx, "client hello verify success")
		clientHelloFrame.Release()

		var serverHelloFrame *buf.Buffer
		serverHelloFrame, err = extractFrame(handshakeConn)
		if err != nil {
			return E.Cause(err, "read server handshake")
		}

		_, err = conn.Write(serverHelloFrame.Bytes())
		if err != nil {
			serverHelloFrame.Release()
			return E.Cause(err, "write server handshake")
		}

		serverRandom := extractServerRandom(serverHelloFrame.Bytes())

		if serverRandom == nil {
			s.logger.WarnContext(ctx, "server random extract failed, will copy bidirectional")
			return bufio.CopyConn(ctx, conn, handshakeConn)
		}

		if s.strictMode && !isServerHelloSupportTLS13(serverHelloFrame.Bytes()) {
			s.logger.WarnContext(ctx, "TLS 1.3 is not supported, will copy bidirectional")
			return bufio.CopyConn(ctx, conn, handshakeConn)
		}

		serverHelloFrame.Release()
		if debug.Enabled {
			s.logger.TraceContext(ctx, "client authenticated. server random extracted: ", hex.EncodeToString(serverRandom))
		}
		hmacWrite := hmac.New(sha1.New, []byte(user.Password))
		hmacWrite.Write(serverRandom)
		hmacAdd := hmac.New(sha1.New, []byte(user.Password))
		hmacAdd.Write(serverRandom)
		hmacAdd.Write([]byte("S"))
		hmacVerify := hmac.New(sha1.New, []byte(user.Password))
		hmacVerifyReset := func() {
			hmacVerify.Reset()
			hmacVerify.Write(serverRandom)
			hmacVerify.Write([]byte("C"))
		}

		var clientFirstFrame *buf.Buffer
		var group task.Group
		var handshakeFinished bool
		group.Append("client handshake relay", func(ctx context.Context) error {
			clientFrame, cErr := copyByFrameUntilHMACMatches(conn, handshakeConn, hmacVerify, hmacVerifyReset)
			if cErr == nil {
				clientFirstFrame = clientFrame
				handshakeFinished = true
				handshakeConn.Close()
			}
			return cErr
		})
		group.Append("server handshake relay", func(ctx context.Context) error {
			cErr := copyByFrameWithModification(handshakeConn, conn, user.Password, serverRandom, hmacWrite)
			if E.IsClosedOrCanceled(cErr) && handshakeFinished {
				return nil
			}
			return cErr
		})
		group.Cleanup(func() {
			handshakeConn.Close()
		})
		err = group.Run(ctx)
		if err != nil {
			return E.Cause(err, "handshake relay")
		}
		s.logger.TraceContext(ctx, "handshake relay finished")
		return s.handler.NewConnection(ctx, bufio.NewCachedConn(newVerifiedConn(conn, hmacAdd, hmacVerify, nil), clientFirstFrame), metadata)
	}
}
