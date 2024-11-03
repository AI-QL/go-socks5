package socks5

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestSocks5_Bind tests the SOCKS5 bind functionality.
func TestSocks5_Bind(t *testing.T) {
	// Create a static credentials map for authentication
	creds := StaticCredentials{
		"foo": "bar",
	}
	// Create an authenticator using the static credentials
	cator := UserPassAuthenticator{Credentials: creds}
	// Configure the SOCKS5 server
	conf := &Config{
		AuthMethods: []Authenticator{cator},
		BindIP:      net.ParseIP("127.0.0.1"),
		Logger:      log.New(os.Stdout, "", log.LstdFlags),
	}
	// Create a new SOCKS5 server with the given configuration
	serv, err := New(conf)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 server: %v", err)
		return
	}
	// Start the server in a separate goroutine
	go func() {
		if err := serv.ListenAndServe("tcp", "127.0.0.1:12367"); err != nil {
			t.Errorf("Failed to start SOCKS5 server: %v", err)
		}
	}()

	// Define a callback to capture the bind port of the SOCKS5 server
	var socks5ServerBindPort int
	cb := func(bindAddr string) {
		_, port, err := net.SplitHostPort(bindAddr)
		if err == nil {
			fmt.Printf("SOCKS5 server bind port %v\n", port)
			socks5ServerBindPort, _ = strconv.Atoi(port)
		}
	}
	BindCallBack = cb

	// Wait for the server to bind to the port
	time.Sleep(10 * time.Millisecond)

	// Create a SOCKS5 dialer to connect to the server
	dial, err := NewDialer("socks5://127.0.0.1:12367")
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 dialer: %v", err)
		return
	}
	dial.Username = "foo"
	dial.Password = "bar"
	// Create a listener to bind to a local port
	listener, err := dial.Listen(context.Background(), "tcp", ":12000")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
		return
	}
	defer listener.Close()

	// Channel to communicate errors from the goroutine
	errCh := make(chan error, 1)

	// Wait for a connection from the SOCKS5 server
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		client, err := listener.Accept()
		if err != nil {
			errCh <- fmt.Errorf("failed to accept connection: %v", err)
			return
		}
		defer client.Close()

		fmt.Printf("Received connection from %v\n", client.LocalAddr().String())

		var bs [4096]byte
		n, err := client.Read(bs[:])
		if err == nil {
			fmt.Printf("=================\nReceived from client:\n%v\n", string(bs[:n]))
			client.Write([]byte("HTTP/1.1 200 OK\r\nServer: sock5\r\nContent-Length: 10\r\n\r\n1234567890"))
		} else {
			errCh <- fmt.Errorf("failed to read from client: %v", err)
		}
	}()
	defer wg.Wait()

	// Wait for the bind port to be set
	for socks5ServerBindPort == 0 {
		time.Sleep(time.Millisecond)
	}

	// Connect to the bound port of the SOCKS5 server
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%v", socks5ServerBindPort))
	if err != nil {
		t.Fatalf("Failed to connect to port %v: %v", socks5ServerBindPort, err)
		return
	}
	defer conn.Close()
	fmt.Printf("Connected to port %v successfully\n", socks5ServerBindPort)

	// Send an HTTP GET request
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	if err != nil {
		t.Fatalf("Failed to send data: %v", err)
		return
	}
	// Set a read deadline to avoid blocking indefinitely
	conn.SetReadDeadline(time.Now().Add(time.Second))
	var bs [4096]byte
	n, err := conn.Read(bs[:])
	if err != nil {
		t.Fatalf("Failed to read data: %v", err)
		return
	}
	fmt.Printf("=================\nHTTP response:\n%v\n\n", string(bs[:n]))

	// Check for any errors from the goroutine
	select {
	case err := <-errCh:
		t.Fatalf("Error from goroutine: %v", err)
	default:
		// No error
	}
}
