package notify

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// BlockedAddressError is returned when a webhook connection targets an address
// that the SSRF guard refuses (loopback, private, link-local, ...).
type BlockedAddressError struct {
	Addr   netip.Addr
	Reason string
}

func (e *BlockedAddressError) Error() string {
	return fmt.Sprintf("connection to %s blocked: %s address (set notifications.allowPrivateNetworks to permit)", e.Addr, e.Reason)
}

var (
	cgnatPrefix     = netip.MustParsePrefix("100.64.0.0/10")
	thisNetPrefix   = netip.MustParsePrefix("0.0.0.0/8")
	ietfPrefix      = netip.MustParsePrefix("192.0.0.0/24")
	benchPrefix     = netip.MustParsePrefix("198.18.0.0/15")
	reservedPrefix  = netip.MustParsePrefix("240.0.0.0/4")
	nat64Prefix     = netip.MustParsePrefix("64:ff9b::/96")
	nat64LocalPref  = netip.MustParsePrefix("64:ff9b:1::/48")
	sixToFourPrefix = netip.MustParsePrefix("2002::/16")
)

// CheckIP reports why ip must not be contacted by a webhook, or nil if it is a
// public unicast address. IPv4-mapped, NAT64 and 6to4 addresses are checked
// against the IPv4 address they embed.
func CheckIP(ip netip.Addr) error {
	reason := blockedReason(ip)
	if reason == "" {
		return nil
	}
	return &BlockedAddressError{Addr: ip, Reason: reason}
}

func blockedReason(ip netip.Addr) string {
	if !ip.IsValid() {
		return "invalid"
	}
	ip = ip.WithZone("")
	if ip.Is4In6() {
		return blockedReason(ip.Unmap())
	}
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsLinkLocalUnicast():
		return "link-local"
	case ip.IsMulticast(), ip.IsLinkLocalMulticast(), ip.IsInterfaceLocalMulticast():
		return "multicast"
	case ip.IsPrivate():
		return "private"
	}
	if ip.Is4() {
		switch {
		case cgnatPrefix.Contains(ip):
			return "carrier-grade NAT"
		case thisNetPrefix.Contains(ip), ietfPrefix.Contains(ip), benchPrefix.Contains(ip), reservedPrefix.Contains(ip):
			return "reserved"
		}
		return ""
	}
	// IPv6 forms that embed an IPv4 address.
	b := ip.As16()
	if nat64Prefix.Contains(ip) || nat64LocalPref.Contains(ip) {
		if r := blockedReason(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})); r != "" {
			return r + " (NAT64)"
		}
	}
	if sixToFourPrefix.Contains(ip) {
		if r := blockedReason(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})); r != "" {
			return r + " (6to4)"
		}
	}
	// Deprecated IPv4-compatible ::a.b.c.d.
	if b[0]|b[1]|b[2]|b[3]|b[4]|b[5]|b[6]|b[7]|b[8]|b[9]|b[10]|b[11] == 0 {
		return "IPv4-compatible"
	}
	return ""
}

// ssrfControl is a net.Dialer Control func that enforces CheckIP on the
// already-resolved address being dialed, so DNS rebinding cannot bypass it.
func ssrfControl(guard func(netip.Addr) error) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("ssrf guard: bad address %q: %w", address, err)
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("ssrf guard: unparsable address %q", host)
		}
		return guard(ip)
	}
}
