package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// UdpPeer records information about a client connection.
type UdpPeer struct {
	updateTime int64       // Timestamp of the last processing
	udpServer  *UdpServer  // The newly created UDP server, can be nil
	from       net.UDPAddr // The client's address
	req        *Request    // The request information
	dst        net.Conn    // The target connection
	atyp       byte        // The target address type
	dstAddr    []byte      // The target address
	dstPort    []byte      // The target port
}

// UdpAssociate manages a collection of UdpPeer instances.
type UdpAssociate struct {
	m map[string]*UdpPeer // Map of UdpPeer instances
}

// Set adds or updates a UdpPeer in the collection.
func (ua *UdpAssociate) Set(key string, u *UdpPeer) {
	ua.m[key] = u
}

// Get retrieves a UdpPeer from the collection.
func (ua *UdpAssociate) Get(key string) (*UdpPeer, bool) {
	v, ok := ua.m[key]
	return v, ok
}

// Del removes a UdpPeer from the collection.
func (ua *UdpAssociate) Del(key string) {
	delete(ua.m, key)
}

// CloseAll closes all target connections in the collection.
func (ua *UdpAssociate) CloseAll() {
	for _, v := range ua.m {
		v.dst.Close()
	}
}

// NewUdpAssociate creates a new UdpAssociate instance.
func NewUdpAssociate() *UdpAssociate {
	return &UdpAssociate{
		m: make(map[string]*UdpPeer),
	}
}

// doAssociate handles the UDP association request.
func doAssociate(ctx context.Context, s *Server, conn conn, req *Request) error {
	// FIXME: TCP and UDP connections must be associated, and UDP connections should be released when the TCP connection is closed.
	// When the client requests UDP forwarding, DST.ADDR and DST.PORT may be local network addresses (after NAT), 0, or multiple connections may connect to the same target address.
	// This can make it impossible for the server to uniquely match them. The server should bind a new port for each:
	//   - If DST.ADDR or DST.PORT is zero.
	//   - If DST.ADDR is a local network address, the server should bind a new port.
	//   - If DST.ADDR is a public address and the target address has not been connected before, the server should reuse the port; otherwise, bind a new port.
	udpServer := newUdpServer()
	// Bind a random port
	err := udpServer.Listen("udp", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("doAssociate Failed to bind UDP server: %v", err)
	}
	_, port, err := net.SplitHostPort(udpServer.LocalAddr().String())
	if err != nil {
		return fmt.Errorf("doAssociate Failed to SplitHostPort: %v", err)
	}
	bindPort, _ := strconv.Atoi(port)
	defer udpServer.Close()

	// Create a memory allocator
	var memCreater MemAllocation
	if s.config.Mem != nil {
		memCreater = s.config.Mem.Create(ctx)
	} else {
		memCreater = new(Mem)
	}
	go func() {
		// Keep the SOCKS5 connection request
		io.Copy(io.Discard, conn.(*net.TCPConn))
	}()

	// Send success response
	bindAddr := AddrSpec{IP: s.config.BindIP, Port: bindPort}
	if err := sendReply(conn, successReply, &bindAddr); err != nil {
		return fmt.Errorf("doAssociate Failed to send reply: %v", err)
	}
	return readFromSrc(ctx, s, req, udpServer, memCreater)
}

// readFromSrc processes data from the client.
func readFromSrc(ctx context.Context, s *Server, req *Request, udpServer *UdpServer, memCreater MemAllocation) error {
	// Create a structure to cache new connections
	peers := NewUdpAssociate()
	// UDP packets cannot exceed 65536 bytes
	bs := make([]byte, 65536)
	var n int
	var from *net.UDPAddr
	var err error
	var datagram *Datagram
	for {
		// Read data from the client
		n, from, err = udpServer.ReadFromUdp(bs)
		if err != nil {
			break
		}
		// Parse the data
		datagram, err = NewDatagramFromByte(ctx, memCreater, bs[:n])
		if err != nil {
			break
		}
		// Process the data
		handleDatagram(ctx, s, req, peers, udpServer, memCreater, from, datagram)
		// Release memory
		datagram.free(ctx)
		datagram = nil
	}
	fmt.Printf("readFromSrc fail: %v\n", err)
	// Release all requests when the SOCKS5 connection ends
	peers.CloseAll()
	if datagram != nil {
		datagram.free(ctx)
	}
	return err
}

// handleDatagram processes data from the client.
func handleDatagram(ctx context.Context, s *Server, req *Request, peers *UdpAssociate,
	udpServer *UdpServer, memCreater MemAllocation,
	from *net.UDPAddr, datagram *Datagram) error {
	// Calculate the key
	key := from.String() + "-" + datagram.Address()

	udpPeer, ok := peers.Get(key)
	if !ok {
		// New connection
		// Attempt to connect
		dial := s.config.Dial
		if dial == nil {
			dial = func(ctx context.Context, net_, addr string) (net.Conn, error) {
				return net.Dial(net_, addr)
			}
		}
		dst, err := dial(ctx, "udp", datagram.Address())
		if err != nil {
			return fmt.Errorf("Connect to %v failed: %v", req.DestAddr, err)
		}
		s.config.Logger.Printf("handleDatagram dial %v success.\n", datagram.Address())

		// Create a new connection
		udpPeer = new(UdpPeer)
		udpPeer.updateTime = time.Now().Unix()
		udpPeer.udpServer = udpServer
		udpPeer.from = *from
		udpPeer.req = req
		udpPeer.dst = dst
		udpPeer.atyp = datagram.ATyp
		// Note: Do not directly reference datagram's reference type data
		udpPeer.dstAddr = make([]byte, len(datagram.DstAddr))
		copy(udpPeer.dstAddr, datagram.DstAddr)
		// Note: Do not directly reference datagram's reference type data
		udpPeer.dstPort = make([]byte, len(datagram.DstPort))
		copy(udpPeer.dstPort, datagram.DstPort)

		peers.Set(key, udpPeer)
		go readFromDst(ctx, s, udpPeer, memCreater)
	}
	// Write data to the target
	_, err := udpPeer.dst.Write(datagram.Data)
	if err != nil {
		// This should generally not happen
		fmt.Printf("udpPeer.dst.Write fail: %v\n", err)
		udpPeer.dst.Close()
		peers.Del(key)
	} else {
		// Update the timestamp
		udpPeer.updateTime = time.Now().Unix()
	}
	return nil
}

// readFromDst processes data from the target address.
func readFromDst(ctx context.Context, s *Server, udpPeer *UdpPeer, memCreater MemAllocation) error {
	bs := make([]byte, 65536)
	var n int
	var err error
	var datagram *Datagram
	for {
		n, err = udpPeer.dst.Read(bs)
		if err != nil {
			break
		}
		datagram = NewDatagram(ctx, memCreater, udpPeer.atyp, udpPeer.dstAddr, udpPeer.dstPort, bs[:n])
		if datagram == nil {
			err = fmt.Errorf("readFromDst NewDatagram fail")
			break
		}
		n = datagram.toBytes(ctx, bs)
		if n <= 0 {
			err = fmt.Errorf("readFromDst NewDatagram packet more than 65536")
			break
		}
		_, err = udpPeer.udpServer.WriteToUDP(bs[:n], &udpPeer.from)
		if err != nil {
			break
		}
		// Update the timestamp
		udpPeer.updateTime = time.Now().Unix()
		// Release memory
		datagram.free(ctx)
		datagram = nil
	}
	if datagram != nil {
		datagram.free(ctx)
	}
	return err
}
