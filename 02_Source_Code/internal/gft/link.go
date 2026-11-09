package gft

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Address types in CONNECT payloads.
const (
	AtypIPv4   = 1
	AtypDomain = 3
	AtypIPv6   = 4
)

// EncodeAddr encodes "host:port" as atyp|addr|port.
func EncodeAddr(hostport string) ([]byte, error) {
	h, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("bad port")
	}
	var out []byte
	if ip := net.ParseIP(h); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, AtypIPv4)
			out = append(out, v4...)
		} else {
			out = append(out, AtypIPv6)
			out = append(out, ip.To16()...)
		}
	} else {
		if len(h) == 0 || len(h) > 255 {
			return nil, errors.New("bad host")
		}
		out = append(out, AtypDomain, byte(len(h)))
		out = append(out, h...)
	}
	out = binary.BigEndian.AppendUint16(out, uint16(port))
	return out, nil
}

// DecodeAddr parses an address; rest is any trailing 0-RTT data.
func DecodeAddr(b []byte) (hostport string, rest []byte, err error) {
	if len(b) < 1 {
		return "", nil, errors.New("short addr")
	}
	var host string
	var off int
	switch b[0] {
	case AtypIPv4:
		if len(b) < 1+4+2 {
			return "", nil, errors.New("short addr")
		}
		host = net.IP(b[1:5]).String()
		off = 5
	case AtypIPv6:
		if len(b) < 1+16+2 {
			return "", nil, errors.New("short addr")
		}
		host = net.IP(b[1:17]).String()
		off = 17
	case AtypDomain:
		if len(b) < 2 || len(b) < 2+int(b[1])+2 || b[1] == 0 {
			return "", nil, errors.New("short addr")
		}
		host = string(b[2 : 2+int(b[1])])
		off = 2 + int(b[1])
	default:
		return "", nil, errors.New("bad atyp")
	}
	port := binary.BigEndian.Uint16(b[off:])
	if port == 0 {
		return "", nil, errors.New("bad port")
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), b[off+2:], nil
}

func UnmarshalParams(b []byte) (Params, error) {
	var p Params
	err := json.Unmarshal(b, &p)
	return p, err
}

// Link is the decoded gft:// link.
type Link struct {
	V      int     `json:"v"`
	Host   string  `json:"host"`
	Port   int     `json:"port"`
	SNI    string  `json:"sni"`
	PSK    string  `json:"psk"` // base64
	Pin    string  `json:"pin"` // sha256 hex of the leaf certificate DER
	Params *Params `json:"params,omitempty"`
	Remark string  `json:"-"`
}

var hostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$`)

func (l *Link) PSKBytes() ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(l.PSK)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(l.PSK)
	}
	return b, err
}

// Validate checks version and all field legality.
func (l *Link) Validate() error {
	if l.V != 1 {
		return fmt.Errorf("unsupported link version %d", l.V)
	}
	if net.ParseIP(l.Host) == nil && !hostRe.MatchString(l.Host) {
		return errors.New("invalid host")
	}
	if l.Port < 1 || l.Port > 65535 {
		return errors.New("invalid port")
	}
	if l.SNI != "" && !hostRe.MatchString(l.SNI) {
		return errors.New("invalid sni")
	}
	psk, err := l.PSKBytes()
	if err != nil || len(psk) < 16 {
		return errors.New("invalid psk (base64, >=16 bytes)")
	}
	if len(l.Pin) != 64 {
		return errors.New("invalid pin (sha256 hex)")
	}
	if _, err := hex.DecodeString(l.Pin); err != nil {
		return errors.New("invalid pin hex")
	}
	if l.Params != nil {
		if err := l.Params.Validate(); err != nil {
			return fmt.Errorf("invalid params: %w", err)
		}
	}
	return nil
}

func (l *Link) Encode() string {
	b, _ := json.Marshal(l)
	s := "gft://" + base64.RawURLEncoding.EncodeToString(b)
	if l.Remark != "" {
		s += "#" + url.PathEscape(l.Remark)
	}
	return s
}

func ParseLink(s string) (*Link, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "gft://") {
		return nil, errors.New("not a gft:// link")
	}
	s = s[len("gft://"):]
	remark := ""
	if i := strings.IndexByte(s, '#'); i >= 0 {
		remark, _ = url.PathUnescape(s[i+1:])
		s = s[:i]
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, errors.New("bad base64url payload")
	}
	var l Link
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&l); err != nil {
		return nil, errors.New("bad json payload")
	}
	l.Remark = remark
	if err := l.Validate(); err != nil {
		return nil, err
	}
	return &l, nil
}
