package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

// Datagram represents a SOCKS5 UDP request or response.
type Datagram struct {
	memCreater MemAllocation
	// RSV is a reserved field, should be set to 0x00 0x00.
	Rsv []byte
	// Frag is the fragment identifier. 0x00 for a complete packet, 1-127 for fragments.
	Frag byte
	// ATyp specifies the type of the DST.ADDR field:
	// - 0x01: IPv4 address
	// - 0x03: Domain name
	// - 0x04: IPv6 address
	ATyp byte
	// DstAddr is the target address the packet is destined for.
	DstAddr []byte
	// DstPort is the target port the packet is destined for.
	DstPort []byte
	// Data is the actual payload to be transmitted.
	Data []byte
}

// free releases the allocated memory for the Datagram.
func (d *Datagram) free(ctx context.Context) {
	d.memCreater.Free(ctx, d.Rsv)
}

// toBytes converts the Datagram to a byte slice.
func (d *Datagram) toBytes(ctx context.Context, buf []byte) int {
	totalLen := 2 + 1 + 1 + len(d.DstAddr) + len(d.DstPort) + len(d.Data)
	if totalLen > len(buf) {
		return -1
	}
	idx := 0
	copy(buf, d.Rsv)
	idx += len(d.Rsv)
	buf[idx] = d.Frag
	idx++
	buf[idx] = d.ATyp
	idx++
	copy(buf[idx:], d.DstAddr)
	idx += len(d.DstAddr)
	copy(buf[idx:], d.DstPort)
	idx += len(d.DstPort)
	copy(buf[idx:], d.Data)
	idx += len(d.Data)
	return totalLen
}

// Address returns the destination address and port in string format.
func (d *Datagram) Address() string {
	var s string
	if d.ATyp == fqdnAddress {
		s = bytes.NewBuffer(d.DstAddr[1:]).String()
	} else {
		s = net.IP(d.DstAddr).String()
	}
	p := strconv.Itoa(int(binary.BigEndian.Uint16(d.DstPort)))
	return net.JoinHostPort(s, p)
}

/*
SOCKS5 UDP Datagram Format:
+-----+------+------+----------+----------+----------+
| RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
+-----+------+------+----------+----------+----------+
|  2  |  1   |  1   | Variable |    2     | Variable |
+-----+------+------+----------+----------+----------+
*/
func NewDatagramFromByte(ctx context.Context, memCreater MemAllocation, bs []byte) (*Datagram, error) {
	// Minimum length required to parse the header fields
	needLen := 4
	dataLen := len(bs)
	if dataLen <= needLen {
		return nil, fmt.Errorf("Datagram Illegal")
	}

	frag := bs[2]
	if frag != 0x00 {
		// Fragmentation is not supported
		return nil, fmt.Errorf("Datagram Not Support Slice Transmission")
	}

	aTyp := bs[3]
	var dstAddr []byte
	var dstPort []byte

	// Parse the destination address based on ATyp
	switch aTyp {
	case ipv4Address:
		// IPv4 address: 4 bytes
		needLen += 4
		if dataLen < needLen {
			return nil, fmt.Errorf("Datagram Illegal")
		}
		dstAddr = bs[needLen-4 : needLen]
	case ipv6Address:
		// IPv6 address: 16 bytes
		needLen += 16
		if dataLen < needLen {
			return nil, fmt.Errorf("Datagram Illegal")
		}
		dstAddr = bs[needLen-16 : needLen]
	case fqdnAddress:
		// Domain name: 1 byte for length, followed by the domain name
		needLen += 1
		if dataLen < needLen {
			return nil, fmt.Errorf("Datagram Illegal")
		}
		domainLen := int(bs[needLen-1])
		if domainLen == 0 {
			return nil, fmt.Errorf("Datagram Illegal")
		}
		needLen += domainLen
		if dataLen < needLen {
			return nil, fmt.Errorf("Datagram Illegal")
		}
		dstAddr = bs[needLen-domainLen : needLen]
	default:
		return nil, fmt.Errorf("Datagram Illegal")
	}

	// Parse the destination port: 2 bytes
	needLen += 2
	if dataLen < needLen {
		return nil, fmt.Errorf("Datagram Illegal")
	}
	dstPort = bs[needLen-2 : needLen]
	if dstPort[0] == 0 && dstPort[1] == 0 {
		return nil, fmt.Errorf("Datagram Illegal")
	}

	// Ensure there is actual data in the packet
	if len(bs[needLen:]) == 0 {
		return nil, fmt.Errorf("Datagram Has No Data")
	}

	// Allocate memory for the Datagram
	buf := memCreater.Alloc(ctx, 2+len(dstAddr)+len(dstPort)+len(bs[needLen:]))
	bufIdx := 0

	datagram := new(Datagram)
	datagram.memCreater = memCreater
	datagram.Rsv = buf[bufIdx : bufIdx+2]
	copy(datagram.Rsv, bs[:2])
	bufIdx += 2
	datagram.Frag = frag
	datagram.ATyp = aTyp
	datagram.DstAddr = buf[bufIdx : bufIdx+len(dstAddr)]
	copy(datagram.DstAddr, dstAddr)
	bufIdx += len(dstAddr)
	datagram.DstPort = buf[bufIdx : bufIdx+len(dstPort)]
	copy(datagram.DstPort, dstPort)
	bufIdx += len(dstPort)
	datagram.Data = buf[bufIdx : bufIdx+len(bs[needLen:])]
	copy(datagram.Data, bs[needLen:])
	return datagram, nil
}

/*
SOCKS5 UDP Datagram Format:
+-----+------+------+----------+----------+----------+
| RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
+-----+------+------+----------+----------+----------+
|  2  |  1   |  1   | Variable |    2     | Variable |
+-----+------+------+----------+----------+----------+
*/
func NewDatagram(ctx context.Context, memCreater MemAllocation, aTyp byte, dstAddr, dstPort, data []byte) *Datagram {
	// Prepend the length of the domain name if it's a domain name (ATyp == 0x03)
	if aTyp == fqdnAddress {
		dstAddr = append([]byte{byte(len(dstAddr))}, dstAddr...)
	}

	// Allocate memory for the Datagram
	buf := memCreater.Alloc(ctx, 2+len(dstAddr)+len(dstPort)+len(data))
	bufIdx := 0

	datagram := new(Datagram)
	datagram.memCreater = memCreater
	datagram.Rsv = buf[bufIdx : bufIdx+2]
	datagram.Rsv[0] = 0x00
	datagram.Rsv[1] = 0x00
	bufIdx += 2
	datagram.Frag = 0x00
	datagram.ATyp = aTyp
	datagram.DstAddr = buf[bufIdx : bufIdx+len(dstAddr)]
	copy(datagram.DstAddr, dstAddr)
	bufIdx += len(dstAddr)
	datagram.DstPort = buf[bufIdx : bufIdx+len(dstPort)]
	copy(datagram.DstPort, dstPort)
	bufIdx += len(dstPort)
	datagram.Data = buf[bufIdx : bufIdx+len(data)]
	copy(datagram.Data, data)
	return datagram
}