package shadowtls

import (
	sTLS "github.com/sagernet/sing-shadowtls/internal/tls"
)

type (
	sTLSConfig               = sTLS.Config
	sTLSConnectionState      = sTLS.ConnectionState
	sTLSConn                 = sTLS.Conn
	sTLSCurveID              = sTLS.CurveID
	sTLSRenegotiationSupport = sTLS.RenegotiationSupport
)

var (
	sTLSCipherSuites = sTLS.CipherSuites
	sTLSClient       = sTLS.Client
)
