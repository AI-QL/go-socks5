package socks5

import (
	"context"
	"net"
)

// NameResolver is an interface used to implement custom name resolution.
// It provides a method to resolve a domain name to an IP address.
type NameResolver interface {
	// Resolve resolves the given domain name to an IP address.
	// ctx can be used to control the resolution process, such as for timeouts or cancellations.
	Resolve(ctx context.Context, name string) (context.Context, net.IP, error)
}

// DNSResolver is a struct that implements the NameResolver interface using the system's DNS resolver.
// It resolves hostnames to IP addresses using the standard library's net package.
type DNSResolver struct{}

// Resolve resolves the given domain name to an IP address using the system's DNS resolver.
// It returns the resolved IP address and any error encountered during the resolution process.
func (d DNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addr, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return ctx, nil, err
	}
	return ctx, addr.IP, nil
}