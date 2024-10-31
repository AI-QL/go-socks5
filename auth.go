package socks5

import (
	"fmt"
	"io"
)

const (
	// NoAuth represents the "No Authentication" method.
	NoAuth = uint8(0)

	// noAcceptable is used to indicate that no acceptable authentication methods are available.
	noAcceptable = uint8(255)

	// UserPassAuth represents the "User/Password Authentication" method.
	UserPassAuth = uint8(2)

	// userAuthVersion is the version number for the user/password authentication method.
	userAuthVersion = uint8(1)

	// authSuccess is the status code for successful authentication.
	authSuccess = uint8(0)

	// authFailure is the status code for failed authentication.
	authFailure = uint8(1)
)

var (
	// UserAuthFailed is an error returned when user authentication fails.
	UserAuthFailed = fmt.Errorf("User authentication failed")

	// NoSupportedAuth is an error returned when no supported authentication mechanisms are available.
	NoSupportedAuth = fmt.Errorf("No supported authentication mechanism")
)

// AuthContext encapsulates authentication state provided during negotiation.
type AuthContext struct {
	// Method is the authentication method used.
	Method uint8

	// Payload contains additional information provided during the authentication process.
	// The keys depend on the used authentication method.
	// For UserPassAuth, it contains the username.
	Payload map[string]string
}

// Authenticator is an interface for handling authentication.
// It provides methods to authenticate a connection and to get the authentication method code.
type Authenticator interface {
	// Authenticate performs the authentication process using the provided reader and writer.
	// It returns an AuthContext if the authentication is successful, and an error if it fails.
	Authenticate(reader io.Reader, writer io.Writer) (*AuthContext, error)

	// GetCode returns the authentication method code.
	GetCode() uint8
}

// NoAuthAuthenticator is an implementation of the Authenticator interface for the "No Authentication" method.
type NoAuthAuthenticator struct{}

// GetCode returns the authentication method code for the "No Authentication" method.
func (a NoAuthAuthenticator) GetCode() uint8 {
	return NoAuth
}

// Authenticate implements the Authenticator interface for the "No Authentication" method.
// It always returns a successful AuthContext with the NoAuth method and an empty payload.
func (a NoAuthAuthenticator) Authenticate(reader io.Reader, writer io.Writer) (*AuthContext, error) {
	_, err := writer.Write([]byte{socks5Version, NoAuth})
	return &AuthContext{Method: NoAuth, Payload: nil}, err
}

// UserPassAuthenticator is an implementation of the Authenticator interface for the "User/Password Authentication" method.
type UserPassAuthenticator struct {
	// Credentials is the credential store used to validate user credentials.
	Credentials CredentialStore
}

// GetCode returns the authentication method code for the "User/Password Authentication" method.
func (a UserPassAuthenticator) GetCode() uint8 {
	return UserPassAuth
}

// Authenticate performs the user/password authentication process.
// It verifies the user credentials and returns an AuthContext if successful.
func (a UserPassAuthenticator) Authenticate(reader io.Reader, writer io.Writer) (*AuthContext, error) {
	// Tell the client to use user/pass auth
	if _, err := writer.Write([]byte{socks5Version, UserPassAuth}); err != nil {
		return nil, err
	}

	// Get the version and username length
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(reader, header, 2); err != nil {
		return nil, err
	}

	// Ensure we are compatible
	if header[0] != userAuthVersion {
		return nil, fmt.Errorf("Unsupported auth version: %v", header[0])
	}

	// Get the user name
	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadAtLeast(reader, user, userLen); err != nil {
		return nil, err
	}

	// Get the password length
	if _, err := reader.Read(header[:1]); err != nil {
		return nil, err
	}

	// Get the password
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(reader, pass, passLen); err != nil {
		return nil, err
	}

	// Verify the password
	if a.Credentials.Valid(string(user), string(pass)) {
		if _, err := writer.Write([]byte{userAuthVersion, authSuccess}); err != nil {
			return nil, err
		}
	} else {
		if _, err := writer.Write([]byte{userAuthVersion, authFailure}); err != nil {
			return nil, err
		}
		return nil, UserAuthFailed
	}

	// Done
	return &AuthContext{Method: UserPassAuth, Payload: map[string]string{"Username": string(user)}}, nil
}

// authenticate handles the connection authentication process.
// It reads the methods supported by the client and selects a usable method.
func (s *Server) authenticate(conn io.Writer, bufConn io.Reader) (*AuthContext, error) {
	// Get the methods
	methods, err := readMethods(bufConn)
	if err != nil {
		return nil, fmt.Errorf("Failed to get auth methods: %v", err)
	}

	// Select a usable method
	for _, method := range methods {
		if cator, found := s.authMethods[method]; found {
			return cator.Authenticate(bufConn, conn)
		}
	}

	// No usable method found
	return nil, noAcceptableAuth(conn)
}

// noAcceptableAuth handles the case when no eligible authentication mechanism is available.
func noAcceptableAuth(conn io.Writer) error {
	conn.Write([]byte{socks5Version, noAcceptable})
	return NoSupportedAuth
}

// readMethods reads the number of methods and the authentication methods supported by the client.
func readMethods(r io.Reader) ([]byte, error) {
	header := []byte{0}
	if _, err := r.Read(header); err != nil {
		return nil, err
	}

	numMethods := int(header[0])
	methods := make([]byte, numMethods)
	_, err := io.ReadAtLeast(r, methods, numMethods)
	return methods, err
}