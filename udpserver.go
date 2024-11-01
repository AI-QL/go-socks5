package socks5

import (
	"net"
)

// udpServer is a global instance of UdpServer.
var udpServer UdpServer

// UdpInstance returns the global UdpServer instance.
func UdpInstance() *UdpServer {
	return &udpServer
}

// UdpServer represents a UDP server that can handle UDP connections.
type UdpServer struct {
	ls *net.UDPConn // The underlying UDP connection.
}

// newUdpServer creates and returns a new UdpServer instance.
func newUdpServer() *UdpServer {
	return new(UdpServer)
}

// Listen initializes the UDP server by binding it to the specified network address.
// It returns an error if the server cannot be bound to the specified address.
func (us *UdpServer) Listen(network, addr string) error {
	udpAddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return err
	}
	us.ls, err = net.ListenUDP(network, udpAddr)
	return err
}

// ReadFromUdp reads a UDP packet from the underlying UDP connection.
// It returns the number of bytes read, the remote address from which the packet was received, and any error encountered.
func (us *UdpServer) ReadFromUdp(bs []byte) (int, *net.UDPAddr, error) {
	return us.ls.ReadFromUDP(bs)
}

// WriteToUDP writes a UDP packet to the specified remote address.
// It returns the number of bytes written and any error encountered.
func (us *UdpServer) WriteToUDP(bs []byte, addr *net.UDPAddr) (int, error) {
	return us.ls.WriteToUDP(bs, addr)
}

// LocalAddr returns the local address to which the UDP server is bound.
func (us *UdpServer) LocalAddr() net.Addr {
	return us.ls.LocalAddr()
}

// Close closes the UDP connection.
// It returns an error if the connection cannot be closed.
func (us *UdpServer) Close() error {
	return us.ls.Close()
}