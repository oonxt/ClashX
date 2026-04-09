package outbound

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	anytls "github.com/anytls/sing-anytls"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
)

type AnyTLS struct {
	*Base
	client *anytls.Client
	option *AnyTLSOption
}

type AnyTLSOption struct {
	BasicOption
	Name                     string   `proxy:"name"`
	Server                   string   `proxy:"server"`
	Port                     int      `proxy:"port"`
	Password                 string   `proxy:"password"`
	ALPN                     []string `proxy:"alpn,omitempty"`
	SNI                      string   `proxy:"sni,omitempty"`
	SkipCertVerify           bool     `proxy:"skip-cert-verify,omitempty"`
	UDP                      bool     `proxy:"udp,omitempty"`
	IdleSessionCheckInterval int      `proxy:"idle-session-check-interval,omitempty"`
	IdleSessionTimeout       int      `proxy:"idle-session-timeout,omitempty"`
	MinIdleSession           int      `proxy:"min-idle-session,omitempty"`
}

func (a *AnyTLS) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	destAddr := M.ParseSocksaddr(metadata.RemoteAddress())
	c, err := a.client.CreateProxy(ctx, destAddr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", a.addr, err)
	}
	return NewConn(c, a), nil
}

func (a *AnyTLS) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	return nil, fmt.Errorf("anytls UDP not supported")
}

func (a *AnyTLS) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	return nil, fmt.Errorf("anytls does not support StreamConn (multiplexed protocol)")
}

func NewAnyTLS(option AnyTLSOption) (*AnyTLS, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	serverName := option.Server
	if option.SNI != "" {
		serverName = option.SNI
	}

	alpn := []string{"h2", "http/1.1"}
	if len(option.ALPN) > 0 {
		alpn = option.ALPN
	}

	tlsConfig := &tls.Config{
		NextProtos:         alpn,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: option.SkipCertVerify,
		ServerName:         serverName,
	}

	idleCheckInterval := 30 * time.Second
	if option.IdleSessionCheckInterval > 0 {
		idleCheckInterval = time.Duration(option.IdleSessionCheckInterval) * time.Second
	}

	idleTimeout := 60 * time.Second
	if option.IdleSessionTimeout > 0 {
		idleTimeout = time.Duration(option.IdleSessionTimeout) * time.Second
	}

	a := &AnyTLS{
		Base: &Base{
			name:  option.Name,
			addr:  addr,
			tp:    C.AnyTLS,
			udp:   option.UDP,
			iface: option.Interface,
			rmark: option.RoutingMark,
		},
		option: &option,
	}

	dialOut := func(ctx context.Context) (net.Conn, error) {
		c, err := dialer.DialContext(ctx, "tcp", addr, a.Base.DialOptions()...)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", addr, err)
		}
		tcpKeepAlive(c)

		tlsConn := tls.Client(c, tlsConfig)
		tlsCtx, cancel := context.WithTimeout(ctx, C.DefaultTLSTimeout)
		defer cancel()
		if err := tlsConn.HandshakeContext(tlsCtx); err != nil {
			c.Close()
			return nil, fmt.Errorf("%s TLS handshake error: %w", addr, err)
		}
		return tlsConn, nil
	}

	client, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
		Password:                 option.Password,
		IdleSessionCheckInterval: idleCheckInterval,
		IdleSessionTimeout:       idleTimeout,
		MinIdleSession:           option.MinIdleSession,
		DialOut:                  dialOut,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create anytls client: %w", err)
	}

	a.client = client
	return a, nil
}
