package outbound

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"

	hy2 "github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
)

type Hysteria2 struct {
	*Base
	client *hy2.Client
	option *Hysteria2Option
}

type Hysteria2Option struct {
	BasicOption
	Name           string   `proxy:"name"`
	Server         string   `proxy:"server"`
	Port           int      `proxy:"port"`
	Password       string   `proxy:"password"`
	Up             string   `proxy:"up,omitempty"`
	Down           string   `proxy:"down,omitempty"`
	Obfs           string   `proxy:"obfs,omitempty"`
	ObfsPassword   string   `proxy:"obfs-password,omitempty"`
	SNI            string   `proxy:"sni,omitempty"`
	ALPN           []string `proxy:"alpn,omitempty"`
	SkipCertVerify bool     `proxy:"skip-cert-verify,omitempty"`
	UDP            bool     `proxy:"udp,omitempty"`
}

func (h *Hysteria2) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	dst := M.ParseSocksaddr(metadata.RemoteAddress())
	c, err := h.client.DialConn(ctx, dst)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", h.addr, err)
	}
	return NewConn(c, h), nil
}

func (h *Hysteria2) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	pc, err := h.client.ListenPacket(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s listen packet error: %w", h.addr, err)
	}
	return newPacketConn(pc, h), nil
}

func (h *Hysteria2) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	return nil, fmt.Errorf("hysteria2 does not support StreamConn (multiplexed protocol)")
}

func NewHysteria2(option Hysteria2Option) (*Hysteria2, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	serverName := option.Server
	if option.SNI != "" {
		serverName = option.SNI
	}

	stdTLS := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: option.SkipCertVerify,
		ServerName:         serverName,
		NextProtos:         option.ALPN,
	}

	salamander := ""
	if option.Obfs == "salamander" {
		salamander = option.ObfsPassword
	}

	h := &Hysteria2{
		Base: &Base{
			name:  option.Name,
			addr:  addr,
			tp:    C.Hysteria2,
			udp:   option.UDP,
			iface: option.Interface,
			rmark: option.RoutingMark,
		},
		option: &option,
	}

	client, err := hy2.NewClient(hy2.ClientOptions{
		Context:            context.Background(),
		Dialer:             newSingDialer(h.Base),
		Logger:             logger.NOP(),
		ServerAddress:      M.ParseSocksaddrHostPort(option.Server, uint16(option.Port)),
		Password:           option.Password,
		SalamanderPassword: salamander,
		TLSConfig:          &singTLSConfig{cfg: stdTLS},
		UDPDisabled:        !option.UDP,
		SendBPS:            parseBandwidth(option.Up),
		ReceiveBPS:         parseBandwidth(option.Down),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create hysteria2 client: %w", err)
	}

	h.client = client
	return h, nil
}

// --- adapters between sing's interfaces and clash's dialer/tls ---

type singDialer struct {
	base *Base
}

func newSingDialer(b *Base) N.Dialer {
	return &singDialer{base: b}
}

func (d *singDialer) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	return dialer.DialContext(ctx, network, dst.String(), d.base.DialOptions()...)
}

func (d *singDialer) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	return dialer.ListenPacket(ctx, "udp", "", d.base.DialOptions()...)
}

type singTLSConfig struct {
	cfg *tls.Config
}

func (c *singTLSConfig) ServerName() string             { return c.cfg.ServerName }
func (c *singTLSConfig) SetServerName(s string)         { c.cfg.ServerName = s }
func (c *singTLSConfig) NextProtos() []string           { return c.cfg.NextProtos }
func (c *singTLSConfig) SetNextProtos(p []string)       { c.cfg.NextProtos = p }
func (c *singTLSConfig) STDConfig() (*tls.Config, error) { return c.cfg, nil }
func (c *singTLSConfig) Client(conn net.Conn) (aTLS.Conn, error) {
	return &singTLSConn{Conn: tls.Client(conn, c.cfg)}, nil
}
func (c *singTLSConfig) Clone() aTLS.Config {
	return &singTLSConfig{cfg: c.cfg.Clone()}
}

type singTLSConn struct {
	*tls.Conn
}

func (c *singTLSConn) NetConn() net.Conn { return c.Conn.NetConn() }
func (c *singTLSConn) ConnectionState() aTLS.ConnectionState {
	return c.Conn.ConnectionState()
}

// parseBandwidth parses strings like "100 mbps" / "10mbps" into bits/sec.
// Returns 0 when the input is empty or unparseable, which means "unspecified".
func parseBandwidth(s string) uint64 {
	if s == "" {
		return 0
	}
	var n uint64
	var unit string
	for i, r := range s {
		if r < '0' || r > '9' {
			fmt.Sscanf(s[:i], "%d", &n)
			unit = s[i:]
			break
		}
	}
	if n == 0 {
		fmt.Sscanf(s, "%d", &n)
		return n
	}
	switch {
	case len(unit) == 0:
		return n
	default:
		switch unit[0] {
		case ' ', '\t':
			unit = unit[1:]
		}
	}
	switch unit {
	case "bps":
		return n
	case "kbps":
		return n * 1000
	case "mbps":
		return n * 1000 * 1000
	case "gbps":
		return n * 1000 * 1000 * 1000
	case "tbps":
		return n * 1000 * 1000 * 1000 * 1000
	}
	return 0
}
