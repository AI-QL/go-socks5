package socks5

import (
	"context"
	"fmt"
	"net"
	"strconv"
)

// BindCallBackFun is a function type for the callback that will be triggered when a bind operation is successful.
type BindCallBackFun func(bindAddr string)

// BindCallBack is a global variable that stores the callback function for bind operations.
var BindCallBack BindCallBackFun

// doBind handles the BIND command of the SOCKS5 protocol.
// It listens on a random port, sends the bind address back to the client, and waits for an incoming connection.
func doBind(ctx context.Context, s *Server, conn conn, req *Request) error {
	// Listen on a random TCP port.
	listenTcp, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		s.config.Logger.Printf("doBind Listen fail: %v\n", err)
		sendReply(conn, serverFailure, nil)
		return err
	}
	defer listenTcp.Close()
	s.config.Logger.Printf("doBind Listen %v\n", listenTcp.Addr().String())
	if BindCallBack != nil {
		BindCallBack(listenTcp.Addr().String())
	}

	// Extract the bound port from the listener address.
	_, port, err := net.SplitHostPort(listenTcp.Addr().String())
	if err != nil {
		return fmt.Errorf("doBind Failed to SplitHostPort: %v", err)
	}
	bindPort, _ := strconv.Atoi(port)

	// Send the bind address back to the client.
	bindAddr := AddrSpec{IP: s.config.BindIP, Port: bindPort}
	if err = sendReply(conn, successReply, &bindAddr); err != nil {
		return fmt.Errorf("doBind Failed to send reply: %v", err)
	}

	// Accept an incoming connection.
	var tcpConn net.Conn
	for {
		tcpConn, err = listenTcp.Accept()
		if err != nil {
			s.config.Logger.Printf("doBind Accept fail: %v\n", err)
			sendReply(conn, serverFailure, nil)
			return err
		}

		// TODO: Consider implementing IP restriction to only accept connections from the target IP.
		// remoteIp, _, _ := net.SplitHostPort(tcpConn.RemoteAddr().String())
		// if remoteIp != req.DestAddr.IP.String() {
		// 	tcpConn.Close()
		// 	continue
		// }

		s.config.Logger.Printf("doBind accept one connection from %v\n", tcpConn.RemoteAddr().String())
		break
	}
	defer tcpConn.Close()

	// Extract the remote IP and port from the accepted connection.
	remoteIp, port, err := net.SplitHostPort(tcpConn.RemoteAddr().String())
	if err != nil {
		s.config.Logger.Printf("doBind Failed to SplitHostPort accept tcp addr: %v\n", err)
		sendReply(conn, serverFailure, nil)
		return err
	}
	remotePort, _ := strconv.Atoi(port)

	// Send the accepted connection address back to the client.
	acceptAddr := AddrSpec{IP: net.ParseIP(remoteIp), Port: remotePort}
	if err = sendReply(conn, successReply, &acceptAddr); err != nil {
		return fmt.Errorf("doBind Failed to send reply: %v", err)
	}

	// Set up a channel to handle errors from the proxy goroutines.
	errCh := make(chan error, 2)
	go proxy(tcpConn, req.bufConn, errCh)
	go proxy(conn, tcpConn, errCh)

	// Wait for both proxy goroutines to finish.
	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			// Return from this function to close the connections.
			return e
		}
	}
	return nil
}