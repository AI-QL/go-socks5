package socks5

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
)

const (
	socks5Version = uint8(5)
)

// Config is used to setup and configure a Server.
type Config struct {
	// AuthMethods can be provided to implement custom authentication.
	// By default, "auth-less" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	AuthMethods []Authenticator

	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and AuthMethods is nil, then "auth-less" mode is enabled.
	Credentials CredentialStore

	// Resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	Resolver NameResolver

	// Rules is provided to enable custom logic around permitting
	// various commands. If not provided, PermitAll is used.
	Rules RuleSet

	// Rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	Rewriter AddressRewriter

	// BindIP is used for bind or UDP associate.
	BindIP net.IP

	// Logger can be used to provide a custom log target.
	// Defaults to stdout.
	Logger *log.Logger

	// Dial is an optional function for dialing out.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	// Mem is the memory allocator.
	Mem MemMgr
}

// Server is responsible for accepting connections and handling
// the details of the SOCKS5 protocol.
type Server struct {
	// config contains the server configuration.
	config *Config

	// authMethods maps authentication methods to their respective
	// Authenticator implementations.
	authMethods map[uint8]Authenticator
}

// New creates a new Server instance and potentially returns an error if the configuration is invalid.
//
// It ensures that the following defaults are set if not explicitly provided in the configuration:
// - At least one authentication method is enabled. If no methods are specified, it defaults to using a
//   UserPassAuthenticator if credentials are provided, or a NoAuthAuthenticator if no credentials are provided.
// - A DNS resolver is set. If not provided, it defaults to a DNSResolver.
// - A rule set is set. If not provided, it defaults to PermitAll.
// - A log target is set. If not provided, it defaults to logging to standard output with standard log flags.
//
// Parameters:
//   conf - The configuration for the server.
//
// Returns:
//   A new Server instance and any error that might have occurred.
func New(conf *Config) (*Server, error) {
	// Ensure we have at least one authentication method enabled
	if len(conf.AuthMethods) == 0 {
		if conf.Credentials != nil {
			conf.AuthMethods = []Authenticator{&UserPassAuthenticator{conf.Credentials}}
		} else {
			conf.AuthMethods = []Authenticator{&NoAuthAuthenticator{}}
		}
	}

	// Ensure we have a DNS resolver
	if conf.Resolver == nil {
		conf.Resolver = DNSResolver{}
	}

	// Ensure we have a rule set
	if conf.Rules == nil {
		conf.Rules = PermitAll()
	}

	// Ensure we have a log target
	if conf.Logger == nil {
		conf.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	server := &Server{
		config: conf,
	}

	server.authMethods = make(map[uint8]Authenticator)

	for _, a := range conf.AuthMethods {
		server.authMethods[a.GetCode()] = a
	}

	return server, nil
}

// ListenAndServe creates a listener on the specified network address and starts serving connections.
// It is a convenience function that calls net.Listen and then Serve.
//
// network and addr are the network type and address to listen on, respectively.
// For example, "tcp" and "0.0.0.0:8080".
//
// ListenAndServe returns an error if it fails to create the listener or if there is an error serving connections.
func (s *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Serve accepts incoming connections from the provided listener and handles them.
// It runs in a loop, accepting connections and spawning a goroutine to handle each one using ServeConn.
//
// Serve returns an error if there is an error accepting a connection.
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.ServeConn(conn)
	}
	return nil
}

// ServeConn handles a single connection.
// It reads from the connection, processes the SOCKS5 protocol, and handles the request.
//
// ServeConn performs the following steps:
// 1. Reads the version byte from the connection.
// 2. Checks if the version is compatible with SOCKS5.
// 3. Authenticates the connection based on the server's configuration.
// 4. Reads the client's request.
// 5. Processes the client's request and sends the appropriate response.
//
// ServeConn returns an error if any step fails.
func (s *Server) ServeConn(conn net.Conn) error {
	defer conn.Close()
	bufConn := bufio.NewReader(conn)

	// Read the version byte
	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		s.config.Logger.Printf("[ERR] socks: Failed to get version byte: %v", err)
		return err
	}

	// Ensure we are compatible with SOCKS5
	if version[0] != socks5Version {
		err := fmt.Errorf("Unsupported SOCKS version: %v", version)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}

	// Authenticate the connection
	authContext, err := s.authenticate(conn, bufConn)
	if err != nil {
		err = fmt.Errorf("Failed to authenticate: %v", err)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}

	// Read the client's request
	request, err := NewRequest(bufConn)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, addrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
		}
		return fmt.Errorf("Failed to read destination address: %v", err)
	}
	request.AuthContext = authContext
	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		request.RemoteAddr = &AddrSpec{IP: client.IP, Port: client.Port}
	}

	// Process the client request
	if err := s.handleRequest(request, conn); err != nil {
		err = fmt.Errorf("Failed to handle request: %v", err)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}

	return nil
}