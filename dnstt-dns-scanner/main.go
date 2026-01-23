package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	// Default number of concurrent threads for scanning
	defaultThreads = 50
	// Default timeout for DNS queries
	defaultTimeout = 10 * time.Second
	// How many bytes of random padding to insert into queries (matches dnstt-client)
	numPadding = 3
)

// base32Encoding is a base32 encoding without padding (matches dnstt-client)
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type scanResult struct {
	ip                string
	working           bool
	hasEDNS           bool
	dnsttCompatible   bool
	hasTunnelResponse bool // True if we got a TXT response from tunnel server
	errorMsg          string
	latency           time.Duration
}

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}

// testDNSServer tests if a DNS server at the given IP address responds to queries.
// If testDomain is provided, it queries that domain directly instead of creating a subdomain.
// If expectedTXT is provided, it verifies the TXT response matches.
// Returns: working, hasEDNS, latency, error
func testDNSServer(ip string, domain dns.Name, timeout time.Duration, testDomain dns.Name, expectedTXT string) (bool, bool, time.Duration, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, "53"))
	if err != nil {
		return false, false, 0, err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return false, false, 0, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	var queryName dns.Name
	if len(testDomain) > 0 {
		queryName = testDomain
	} else {
		testLabels := make([][]byte, 0, len(domain)+1)
		testLabels = append(testLabels, []byte("test"))
		testLabels = append(testLabels, domain...)
		queryName, err = dns.NewName(testLabels)
		if err != nil {
			return false, false, 0, fmt.Errorf("failed to create test name: %v", err)
		}
	}

	var id uint16
	binary.Read(rand.Reader, binary.BigEndian, &id)
	query := &dns.Message{
		ID:    id,
		Flags: 0x0100, // QR = 0, RD = 1
		Question: []dns.Question{
			{
				Name:  queryName,
				Type:  dns.RRTypeTXT,
				Class: dns.ClassIN,
			},
		},
		// EDNS(0)
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: 4096, // requester's UDP payload size
				TTL:   0,    // extended RCODE and flags
				Data:  []byte{},
			},
		},
	}

	queryBytes, err := query.WireFormat()
	if err != nil {
		return false, false, 0, fmt.Errorf("failed to encode query: %v", err)
	}

	start := time.Now()
	_, err = conn.Write(queryBytes)
	if err != nil {
		return false, false, 0, fmt.Errorf("failed to send query: %v", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return false, false, 0, fmt.Errorf("no response: %v", err)
	}

	latency := time.Since(start)

	resp, err := dns.MessageFromWireFormat(buf[:n])
	if err != nil {
		return false, false, latency, fmt.Errorf("invalid DNS response: %v", err)
	}

	if resp.Flags&0x8000 == 0 {
		return false, false, latency, fmt.Errorf("not a DNS response")
	}

	if resp.ID != id {
		return false, false, latency, fmt.Errorf("response ID mismatch")
	}

	// Check for EDNS(0) support in response (important for dnstt-client)
	// dnstt-client needs EDNS(0) for larger UDP payload sizes
	hasEDNS := false
	for _, rr := range resp.Additional {
		if rr.Type == dns.RRTypeOPT {
			hasEDNS = true
			break
		}
	}

	if expectedTXT != "" {
		found := false
		for _, answer := range resp.Answer {
			if answer.Type == dns.RRTypeTXT {
				txtData := answer.Data
				var txtValue strings.Builder
				for len(txtData) > 0 {
					if len(txtData) < 1 {
						break
					}
					strLen := int(txtData[0])
					txtData = txtData[1:]
					if len(txtData) < strLen {
						break
					}
					txtValue.Write(txtData[:strLen])
					txtData = txtData[strLen:]
				}
				if txtValue.String() == expectedTXT {
					found = true
					break
				}
			}
		}
		if !found {
			return false, hasEDNS, latency, fmt.Errorf("TXT response does not match expected value %q", expectedTXT)
		}
	}

	return true, hasEDNS, latency, nil
}

// chunks breaks p into non-empty subslices of at most n bytes (matches dnstt-client)
func chunks(p []byte, n int) [][]byte {
	var result [][]byte
	for len(p) > 0 {
		sz := len(p)
		if sz > n {
			sz = n
		}
		result = append(result, p[:sz])
		p = p[sz:]
	}
	return result
}

// dnsNameCapacity returns the number of bytes remaining for encoded data after
// including domain in a DNS name (copied from dnstt-client).
func dnsNameCapacity(domain dns.Name) int {
	capacity := 255
	capacity -= 1
	for _, label := range domain {
		capacity -= len(label) + 1
	}
	capacity = capacity * 63 / 64
	capacity = capacity * 5 / 8
	return capacity
}

// ScannerDNSPacketConn provides a net.PacketConn interface over DNS for use with KCP.
type ScannerDNSPacketConn struct {
	clientID  turbotunnel.ClientID
	domain    dns.Name
	transport *net.UDPConn
	timeout   time.Duration

	remoteAddr net.Addr
	pollChan   chan struct{}
	*turbotunnel.QueuePacketConn

	closed    chan struct{}
	closeOnce sync.Once
}

func NewScannerDNSPacketConn(transport *net.UDPConn, domain dns.Name, timeout time.Duration) *ScannerDNSPacketConn {
	clientID := turbotunnel.NewClientID()
	remoteAddr := turbotunnel.DummyAddr{}
	c := &ScannerDNSPacketConn{
		clientID:        clientID,
		domain:          domain,
		transport:       transport,
		timeout:         timeout,
		remoteAddr:      remoteAddr,
		pollChan:        make(chan struct{}, 16),
		QueuePacketConn: turbotunnel.NewQueuePacketConn(clientID, 0),
		closed:          make(chan struct{}),
	}

	go c.recvLoop()
	go c.sendLoop()

	return c
}

func (c *ScannerDNSPacketConn) recvLoop() {
	for {
		select {
		case <-c.closed:
			return
		default:
		}

		buf := make([]byte, 4096)
		c.transport.SetReadDeadline(time.Now().Add(c.timeout / 2))
		n, err := c.transport.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-c.closed:
				return
			default:
				continue
			}
		}

		// Parse DNS response
		resp, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			continue
		}

		payload := c.dnsResponsePayload(&resp)
		if payload == nil {
			continue
		}

		r := bytes.NewReader(payload)
		anyData := false
		for {
			var pktLen uint16
			err := binary.Read(r, binary.BigEndian, &pktLen)
			if err != nil {
				break
			}
			pkt := make([]byte, pktLen)
			_, err = io.ReadFull(r, pkt)
			if err != nil {
				break
			}
			c.QueuePacketConn.QueueIncoming(pkt, c.remoteAddr)
			anyData = true
		}

		if anyData {
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
		}
	}
}

func (c *ScannerDNSPacketConn) sendLoop() {
	pollTimer := time.NewTimer(50 * time.Millisecond)
	defer pollTimer.Stop()

	for {
		var p []byte
		outgoing := c.QueuePacketConn.OutgoingQueue(c.remoteAddr)

		select {
		case <-c.closed:
			return
		case p = <-outgoing:
		default:
			select {
			case <-c.closed:
				return
			case p = <-outgoing:
			case <-c.pollChan:
				p = nil
			case <-pollTimer.C:
				p = nil
			}
		}

		pollTimer.Reset(100 * time.Millisecond)
		err := c.send(p)
		if err != nil {
			continue
		}
	}
}

func (c *ScannerDNSPacketConn) send(p []byte) error {
	if len(p) >= 224 {
		return fmt.Errorf("packet too long: %d >= 224", len(p))
	}

	var buf bytes.Buffer
	buf.Write(c.clientID[:])
	n := numPadding
	if len(p) == 0 {
		n = 8
	}
	buf.WriteByte(byte(224 + n))
	io.CopyN(&buf, rand.Reader, int64(n))
	if len(p) > 0 {
		buf.WriteByte(byte(len(p)))
		buf.Write(p)
	}
	decoded := buf.Bytes()

	encoded := make([]byte, base32Encoding.EncodedLen(len(decoded)))
	base32Encoding.Encode(encoded, decoded)
	encoded = bytes.ToLower(encoded)
	labels := chunks(encoded, 63)
	labels = append(labels, c.domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return err
	}

	var id uint16
	binary.Read(rand.Reader, binary.BigEndian, &id)
	query := &dns.Message{
		ID:    id,
		Flags: 0x0100,
		Question: []dns.Question{
			{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN},
		},
		Additional: []dns.RR{
			{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 4096, TTL: 0, Data: []byte{}},
		},
	}

	queryBytes, err := query.WireFormat()
	if err != nil {
		return err
	}

	c.transport.SetWriteDeadline(time.Now().Add(c.timeout))
	_, err = c.transport.Write(queryBytes)
	return err
}

func (c *ScannerDNSPacketConn) dnsResponsePayload(resp *dns.Message) []byte {
	if resp.Flags&0x8000 != 0x8000 {
		return nil
	}
	if resp.Flags&0x000f != dns.RcodeNoError {
		return nil
	}
	if len(resp.Answer) != 1 {
		return nil
	}
	answer := resp.Answer[0]
	_, ok := answer.Name.TrimSuffix(c.domain)
	if !ok {
		return nil
	}
	if answer.Type != dns.RRTypeTXT {
		return nil
	}
	payload, err := dns.DecodeRDataTXT(answer.Data)
	if err != nil {
		return nil
	}
	return payload
}

func (c *ScannerDNSPacketConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return nil
}

// testDNSTTEncoding tests the full protocol stack: DNS -> KCP -> Noise -> smux -> SOCKS5.
func testDNSTTEncoding(ip string, domain dns.Name, pubkey []byte, timeout time.Duration, quick bool) (bool, bool, time.Duration, error) {
	startTime := time.Now()

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, "53"))
	if err != nil {
		return false, false, 0, err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return false, false, 0, err
	}
	defer conn.Close()

	pconn := NewScannerDNSPacketConn(conn, domain, timeout)
	defer pconn.Close()

	mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1
	if mtu < 80 {
		return false, false, time.Since(startTime), fmt.Errorf("domain too long, MTU=%d", mtu)
	}

	kcpConn, err := kcp.NewConn2(pconn.remoteAddr, nil, 0, 0, pconn)
	if err != nil {
		return false, false, time.Since(startTime), fmt.Errorf("KCP setup failed: %v", err)
	}
	defer kcpConn.Close()

	kcpConn.SetStreamMode(true)
	kcpConn.SetNoDelay(0, 0, 0, 1)
	kcpConn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if !kcpConn.SetMtu(mtu) {
		return false, false, time.Since(startTime), fmt.Errorf("failed to set MTU")
	}

	kcpConn.SetDeadline(time.Now().Add(timeout * 3))

	noiseConn, err := noise.NewClient(kcpConn, pubkey)
	if err != nil {
		latency := time.Since(startTime)
		// Check if it's a timeout - that means DNS worked but no tunnel server
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return true, false, latency, fmt.Errorf("noise handshake timeout (DNS works, tunnel server not responding)")
		}
		return false, false, latency, fmt.Errorf("noise handshake failed: %v", err)
	}
	defer noiseConn.Close()

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = timeout * 2
	smuxConfig.MaxStreamBuffer = 64 * 1024

	sess, err := smux.Client(noiseConn, smuxConfig)
	if err != nil {
		return true, false, time.Since(startTime), fmt.Errorf("smux setup failed (but Noise worked): %v", err)
	}
	defer sess.Close()

	// Test 1: First HTTP request (basic connectivity)
	err = testHTTPRequest(sess, timeout, "example.com", 1)
	if err != nil {
		return true, false, time.Since(startTime), fmt.Errorf("first HTTP request failed: %v", err)
	}

	if quick {
		latency := time.Since(startTime)
		return true, true, latency, nil
	}

	// Test 2: Open a second stream and make another request
	// This tests if the DNS resolver handles multiple concurrent streams
	err = testHTTPRequest(sess, timeout, "example.com", 2)
	if err != nil {
		return true, false, time.Since(startTime), fmt.Errorf("second HTTP request failed (DNS may rate-limit): %v", err)
	}

	// Test 3: Transfer more data to test sustained throughput
	// Some DNS resolvers work for small amounts but fail under load
	err = testDataTransfer(sess, timeout)
	if err != nil {
		return true, false, time.Since(startTime), fmt.Errorf("data transfer test failed (DNS may have throughput issues): %v", err)
	}

	// Test 4: Open multiple streams rapidly to test connection stability
	err = testMultipleStreams(sess, timeout, 3)
	if err != nil {
		return true, false, time.Since(startTime), fmt.Errorf("multiple streams test failed (DNS may reset connections): %v", err)
	}

	// Test 5: Bidirectional communication test (like HTTP/2 or SSH)
	// This tests if DNS resolver maintains connection for multiple send/receive cycles
	// Catches resolvers that stop responding mid-connection
	err = testBidirectionalCommunication(sess, timeout)
	if err != nil {
		return true, false, time.Since(startTime), fmt.Errorf("bidirectional communication test failed (DNS stops mid-connection): %v", err)
	}

	latency := time.Since(startTime)
	return true, true, latency, nil
}

// testHTTPRequest opens a new stream and performs a complete HTTP request/response cycle
func testHTTPRequest(sess *smux.Session, timeout time.Duration, host string, reqNum int) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("stream open failed: %v", err)
	}
	defer stream.Close()

	stream.SetDeadline(time.Now().Add(timeout * 2))

	socks5Handshake := []byte{0x05, 0x01, 0x00}
	_, err = stream.Write(socks5Handshake)
	if err != nil {
		return fmt.Errorf("SOCKS5 handshake write failed: %v", err)
	}

	response := make([]byte, 2)
	_, err = io.ReadFull(stream, response)
	if err != nil {
		return fmt.Errorf("SOCKS5 handshake read failed: %v", err)
	}

	if response[0] != 0x05 || response[1] != 0x00 {
		return fmt.Errorf("invalid SOCKS5 response: %02x %02x", response[0], response[1])
	}

	targetPort := uint16(80)
	var connectReq bytes.Buffer
	connectReq.WriteByte(0x05)
	connectReq.WriteByte(0x01)
	connectReq.WriteByte(0x00)
	connectReq.WriteByte(0x03)
	connectReq.WriteByte(byte(len(host)))
	connectReq.WriteString(host)
	connectReq.WriteByte(byte(targetPort >> 8))
	connectReq.WriteByte(byte(targetPort & 0xff))

	_, err = stream.Write(connectReq.Bytes())
	if err != nil {
		return fmt.Errorf("SOCKS5 CONNECT write failed: %v", err)
	}

	connectResp := make([]byte, 10)
	_, err = io.ReadFull(stream, connectResp)
	if err != nil {
		return fmt.Errorf("SOCKS5 CONNECT read failed: %v", err)
	}

	if connectResp[0] != 0x05 {
		return fmt.Errorf("SOCKS5 CONNECT: invalid version %02x", connectResp[0])
	}
	if connectResp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 CONNECT failed: reply code %02x", connectResp[1])
	}

	httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	_, err = stream.Write([]byte(httpReq))
	if err != nil {
		return fmt.Errorf("HTTP request write failed: %v", err)
	}

	httpResp := make([]byte, 4096)
	n, err := stream.Read(httpResp)
	if err != nil && err != io.EOF {
		return fmt.Errorf("HTTP response read failed: %v", err)
	}

	respStr := strings.ToLower(string(httpResp[:n]))
	if !strings.Contains(respStr, "example domain") {
		return fmt.Errorf("HTTP response does not contain 'example domain' (got %d bytes)", n)
	}

	return nil
}

// testDataTransfer tests sustained data transfer by downloading more content
// This catches DNS resolvers that work for small transfers but fail under load
func testDataTransfer(sess *smux.Session, timeout time.Duration) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("stream open failed: %v", err)
	}
	defer stream.Close()

	stream.SetDeadline(time.Now().Add(timeout * 3))

	// SOCKS5 handshake
	socks5Handshake := []byte{0x05, 0x01, 0x00}
	_, err = stream.Write(socks5Handshake)
	if err != nil {
		return fmt.Errorf("SOCKS5 handshake write failed: %v", err)
	}

	response := make([]byte, 2)
	_, err = io.ReadFull(stream, response)
	if err != nil {
		return fmt.Errorf("SOCKS5 handshake read failed: %v", err)
	}

	if response[0] != 0x05 || response[1] != 0x00 {
		return fmt.Errorf("invalid SOCKS5 response: %02x %02x", response[0], response[1])
	}

	host := "httpbin.org"
	targetPort := uint16(80)
	var connectReq bytes.Buffer
	connectReq.WriteByte(0x05)
	connectReq.WriteByte(0x01)
	connectReq.WriteByte(0x00)
	connectReq.WriteByte(0x03)
	connectReq.WriteByte(byte(len(host)))
	connectReq.WriteString(host)
	connectReq.WriteByte(byte(targetPort >> 8))
	connectReq.WriteByte(byte(targetPort & 0xff))

	_, err = stream.Write(connectReq.Bytes())
	if err != nil {
		return fmt.Errorf("SOCKS5 CONNECT write failed: %v", err)
	}

	connectResp := make([]byte, 10)
	_, err = io.ReadFull(stream, connectResp)
	if err != nil {
		return fmt.Errorf("SOCKS5 CONNECT read failed: %v", err)
	}

	if connectResp[0] != 0x05 || connectResp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 CONNECT failed: %02x %02x", connectResp[0], connectResp[1])
	}

	httpReq := "GET /bytes/2048 HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"
	_, err = stream.Write([]byte(httpReq))
	if err != nil {
		return fmt.Errorf("HTTP request write failed: %v", err)
	}

	totalRead := 0
	buf := make([]byte, 4096)
	for {
		n, err := stream.Read(buf)
		totalRead += n
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("data transfer read failed after %d bytes: %v", totalRead, err)
		}

		if totalRead > 2500 {
			break
		}
	}

	if totalRead < 2000 {
		return fmt.Errorf("insufficient data received: %d bytes (expected ~2KB)", totalRead)
	}

	return nil
}

// testMultipleStreams opens multiple streams rapidly to test connection stability
// Some DNS resolvers reset connections when too many queries come in quick succession
func testMultipleStreams(sess *smux.Session, timeout time.Duration, count int) error {
	var wg sync.WaitGroup
	errChan := make(chan error, count)

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(streamNum int) {
			defer wg.Done()
			stream, err := sess.OpenStream()
			if err != nil {
				errChan <- fmt.Errorf("stream %d open failed: %v", streamNum, err)
				return
			}
			defer stream.Close()

			stream.SetDeadline(time.Now().Add(timeout))

			// Just do SOCKS5 handshake to test stream stability
			socks5Handshake := []byte{0x05, 0x01, 0x00}
			_, err = stream.Write(socks5Handshake)
			if err != nil {
				errChan <- fmt.Errorf("stream %d write failed: %v", streamNum, err)
				return
			}

			response := make([]byte, 2)
			_, err = io.ReadFull(stream, response)
			if err != nil {
				errChan <- fmt.Errorf("stream %d read failed: %v", streamNum, err)
				return
			}

			if response[0] != 0x05 || response[1] != 0x00 {
				errChan <- fmt.Errorf("stream %d invalid SOCKS5: %02x %02x", streamNum, response[0], response[1])
				return
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	var errors []string
	for err := range errChan {
		errors = append(errors, err.Error())
	}

	if len(errors) > 0 {
		return fmt.Errorf("%d/%d streams failed: %s", len(errors), count, strings.Join(errors, "; "))
	}

	return nil
}

// testBidirectionalCommunication tests sustained bidirectional data flow on a single stream.
// This simulates protocols like SSH where you send a packet, wait for response, send another.
// Performs 8 request/response cycles on the same connection to catch DNS resolvers that:
// - Stop sending responses after initial queries succeed
// - Stop receiving data mid-connection (like SSH auth failures)
// - Rate-limit or reset connections under sustained bidirectional traffic
func testBidirectionalCommunication(sess *smux.Session, timeout time.Duration) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("stream open failed: %v", err)
	}
	defer stream.Close()

	stream.SetDeadline(time.Now().Add(timeout * 4))

	socks5Handshake := []byte{0x05, 0x01, 0x00}
	_, err = stream.Write(socks5Handshake)
	if err != nil {
		return fmt.Errorf("SOCKS5 handshake write failed: %v", err)
	}

	response := make([]byte, 2)
	_, err = io.ReadFull(stream, response)
	if err != nil {
		return fmt.Errorf("SOCKS5 handshake read failed: %v", err)
	}

	if response[0] != 0x05 || response[1] != 0x00 {
		return fmt.Errorf("invalid SOCKS5 response: %02x %02x", response[0], response[1])
	}

	host := "httpbin.org"
	targetPort := uint16(80)
	var connectReq bytes.Buffer
	connectReq.WriteByte(0x05)
	connectReq.WriteByte(0x01)
	connectReq.WriteByte(0x00)
	connectReq.WriteByte(0x03)
	connectReq.WriteByte(byte(len(host)))
	connectReq.WriteString(host)
	connectReq.WriteByte(byte(targetPort >> 8))
	connectReq.WriteByte(byte(targetPort & 0xff))

	_, err = stream.Write(connectReq.Bytes())
	if err != nil {
		return fmt.Errorf("SOCKS5 CONNECT write failed: %v", err)
	}

	connectResp := make([]byte, 10)
	_, err = io.ReadFull(stream, connectResp)
	if err != nil {
		return fmt.Errorf("SOCKS5 CONNECT read failed: %v", err)
	}

	if connectResp[0] != 0x05 || connectResp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 CONNECT failed: %02x %02x", connectResp[0], connectResp[1])
	}

	const numCycles = 8
	for i := 0; i < numCycles; i++ {
		httpReq := fmt.Sprintf("GET /get?cycle=%d HTTP/1.1\r\nHost: httpbin.org\r\nConnection: keep-alive\r\n\r\n", i)
		_, err = stream.Write([]byte(httpReq))
		if err != nil {
			return fmt.Errorf("cycle %d/%d: write failed (DNS stopped sending): %v", i+1, numCycles, err)
		}

		buf := make([]byte, 4096)
		totalRead := 0
		maxRead := 4096
		deadline := time.Now().Add(10 * time.Second)

		for totalRead < maxRead {
			stream.SetReadDeadline(deadline)
			n, err := stream.Read(buf[totalRead:])
			if err != nil {
				if err == io.EOF {
					if totalRead == 0 {
						return fmt.Errorf("cycle %d/%d: connection closed unexpectedly (DNS stopped receiving)", i+1, numCycles)
					}
					break
				}
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					return fmt.Errorf("cycle %d/%d: read timeout (DNS stopped responding mid-connection)", i+1, numCycles)
				}
				return fmt.Errorf("cycle %d/%d: read failed: %v", i+1, numCycles, err)
			}
			if n == 0 {
				break
			}
			totalRead += n

			respStr := string(buf[:totalRead])
			if strings.Contains(respStr, "\r\n\r\n") {
				headerEnd := strings.Index(respStr, "\r\n\r\n")
				bodyStart := headerEnd + 4
				bodyRead := totalRead - bodyStart
				if bodyRead >= 100 || strings.Contains(respStr, "\"url\":") {
					break
				}
			}
		}

		if totalRead < 100 {
			return fmt.Errorf("cycle %d/%d: insufficient response (%d bytes) - DNS may have stopped mid-transfer", i+1, numCycles, totalRead)
		}

		respStr := strings.ToLower(string(buf[:totalRead]))
		if !strings.Contains(respStr, "http/1.1") && !strings.Contains(respStr, "http/1.0") {
			return fmt.Errorf("cycle %d/%d: invalid HTTP response - DNS may be corrupting data", i+1, numCycles)
		}

		if i < numCycles-1 {
			time.Sleep(150 * time.Millisecond)
		}
	}

	return nil
}

func scanIP(ip string, domain dns.Name, pubkey []byte, timeout time.Duration, testDomain dns.Name, expectedTXT string, quick bool, results chan<- scanResult) {
	working, hasEDNS, latency, err := testDNSServer(ip, domain, timeout, testDomain, expectedTXT)
	result := scanResult{
		ip:      ip,
		working: working,
		hasEDNS: hasEDNS,
		latency: latency,
	}
	if err != nil {
		result.errorMsg = err.Error()
		results <- result
		return
	}

	if working {
		dnsttWorking, hasTunnelResp, dnsttLatency, dnsttErr := testDNSTTEncoding(ip, domain, pubkey, timeout, quick)
		result.dnsttCompatible = dnsttWorking
		result.hasTunnelResponse = hasTunnelResp
		if !dnsttWorking {
			if result.errorMsg == "" {
				result.errorMsg = fmt.Sprintf("dnstt tunnel test failed: %v", dnsttErr)
			} else {
				result.errorMsg += fmt.Sprintf("; dnstt: %v", dnsttErr)
			}
		} else {
			result.latency = dnsttLatency
		}
	}

	results <- result
}

func expandCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %v", err)
	}

	// Get the prefix length (e.g., 24 for /24)
	ones, bits := ipNet.Mask.Size()
	if bits == 0 {
		return nil, fmt.Errorf("invalid network mask")
	}

	var ips []string
	ip := make(net.IP, len(ipNet.IP))
	copy(ip, ipNet.IP)
	ip = ip.Mask(ipNet.Mask)

	for ipNet.Contains(ip) {
		ips = append(ips, ip.String())
		inc(ip)
	}

	if ones >= 24 && len(ips) >= 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

func parseIPsInput(input string) ([]string, error) {
	var allIPs []string

	if _, err := os.Stat(input); err == nil {
		file, err := os.Open(input)
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %v", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			ips, err := parseIPOrCIDR(line)
			if err != nil {
				return nil, fmt.Errorf("file %s line %d: %v", input, lineNum, err)
			}
			allIPs = append(allIPs, ips...)
		}

		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading file: %v", err)
		}
	} else {
		ips, err := parseIPOrCIDR(input)
		if err != nil {
			return nil, err
		}
		allIPs = ips
	}

	seen := make(map[string]bool)
	var uniqueIPs []string
	for _, ip := range allIPs {
		if !seen[ip] {
			seen[ip] = true
			uniqueIPs = append(uniqueIPs, ip)
		}
	}

	return uniqueIPs, nil
}

func parseIPOrCIDR(input string) ([]string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("empty input")
	}

	if strings.Contains(input, "/") {
		return expandCIDR(input)
	}

	ip := net.ParseIP(input)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address or CIDR: %s", input)
	}

	return []string{ip.String()}, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func main() {
	var ipsInput string
	var pubkeyFilename string
	var pubkeyString string
	var threads int
	var timeout time.Duration
	var verbose bool
	var testDomainStr string
	var expectedTXT string
	var quick bool

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s -ips IP_OR_CIDR_OR_FILE (-pubkey PUBKEY|-pubkey-file PUBKEYFILE) DOMAIN [-threads N] [-timeout DURATION] [-verbose] [-output FILE] [-quick]

The -ips flag accepts:
  - CIDR notation (e.g., 192.168.1.0/24)
  - Single IP address (e.g., 192.168.1.1)
  - File path containing IPs or CIDRs (one per line, # for comments)

Examples:
  %[1]s -ips 10.10.0.0/16 -pubkey-file server.pub t.example.com -threads 100
  %[1]s -ips 192.168.1.1 -pubkey-file server.pub t.example.com
  %[1]s -ips ip-list.txt -pubkey 0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff t.example.com -output results.txt
  %[1]s -ips 10.10.0.0/24 -pubkey-file server.pub t.example.com -test-domain test.k.markop.ir -test-txt "TEST RESULT"
  %[1]s -ips 10.10.0.0/16 -pubkey-file server.pub t.example.com -quick

Options:
`, os.Args[0])
		flag.PrintDefaults()
	}

	var outputFile string
	flag.StringVar(&ipsInput, "ips", "", "IP address, CIDR notation, or file path containing IPs/CIDRs (one per line)")
	flag.StringVar(&pubkeyString, "pubkey", "", fmt.Sprintf("server public key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&pubkeyFilename, "pubkey-file", "", "read server public key from file")
	flag.IntVar(&threads, "threads", defaultThreads, "number of concurrent scanning threads")
	flag.DurationVar(&timeout, "timeout", defaultTimeout, "timeout for each DNS query")
	flag.BoolVar(&verbose, "verbose", false, "show all results including failures")
	flag.StringVar(&outputFile, "output", "", "save results to file (default: stdout only)")
	flag.StringVar(&testDomainStr, "test-domain", "", "custom domain to query for DNS server test (e.g., test.k.markop.ir)")
	flag.StringVar(&expectedTXT, "test-txt", "", "expected TXT record value to verify DNS server works correctly")
	flag.BoolVar(&quick, "quick", false, "skip advanced tunnel tests (only perform basic connectivity test)")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	if ipsInput == "" {
		fmt.Fprintf(os.Stderr, "error: -ips is required\n")
		flag.Usage()
		os.Exit(1)
	}

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "error: DOMAIN argument is required\n")
		flag.Usage()
		os.Exit(1)
	}

	domain, err := dns.ParseName(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid domain %+q: %v\n", flag.Arg(0), err)
		os.Exit(1)
	}

	var pubkey []byte
	if pubkeyFilename != "" && pubkeyString != "" {
		fmt.Fprintf(os.Stderr, "only one of -pubkey and -pubkey-file may be used\n")
		os.Exit(1)
	} else if pubkeyFilename != "" {
		var err error
		pubkey, err = readKeyFromFile(pubkeyFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read pubkey from file: %v\n", err)
			os.Exit(1)
		}
	} else if pubkeyString != "" {
		var err error
		pubkey, err = noise.DecodeKey(pubkeyString)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pubkey format error: %v\n", err)
			os.Exit(1)
		}
	}
	if len(pubkey) == 0 {
		fmt.Fprintf(os.Stderr, "the -pubkey or -pubkey-file option is required\n")
		os.Exit(1)
	}

	var testDomain dns.Name
	if testDomainStr != "" {
		var err error
		testDomain, err = dns.ParseName(testDomainStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid test domain %+q: %v\n", testDomainStr, err)
			os.Exit(1)
		}
	}

	ips, err := parseIPsInput(ipsInput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing IPs: %v\n", err)
		os.Exit(1)
	}

	if len(ips) == 0 {
		fmt.Fprintf(os.Stderr, "error: no IPs to scan\n")
		os.Exit(1)
	}

	totalIPs := len(ips)
	fmt.Fprintf(os.Stderr, "Scanning %d IPs from %s with %d threads (timeout: %v)...\n", totalIPs, ipsInput, threads, timeout)
	fmt.Fprintf(os.Stderr, "Domain: %s\n", flag.Arg(0))
	if quick {
		fmt.Fprintf(os.Stderr, "Mode: Quick (basic connectivity test only)\n")
	} else {
		fmt.Fprintf(os.Stderr, "Mode: Full (all tunnel tests including bidirectional communication)\n")
	}
	if testDomainStr != "" {
		fmt.Fprintf(os.Stderr, "Test domain: %s\n", testDomainStr)
		if expectedTXT != "" {
			fmt.Fprintf(os.Stderr, "Expected TXT: %q\n", expectedTXT)
		}
	}
	fmt.Fprintf(os.Stderr, "Press Ctrl+C to stop\n\n")

	results := make(chan scanResult, threads*2)
	ipChan := make(chan string, threads*2)

	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintf(os.Stderr, "\n\nInterrupted! Stopping scan...\n")
		cancel()
	}()

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ip, ok := <-ipChan:
					if !ok {
						return
					}
					scanIP(ip, domain, pubkey, timeout, testDomain, expectedTXT, quick, results)
				}
			}
		}()
	}

	var scanned int64
	var workingCount int64

	var resultWg sync.WaitGroup
	resultWg.Add(1)
	workingServers := []scanResult{}
	var resultMutex sync.Mutex

	go func() {
		defer resultWg.Done()
		for result := range results {
			atomic.AddInt64(&scanned, 1)
			current := atomic.LoadInt64(&scanned)

			resultMutex.Lock()
			if result.working {
				atomic.AddInt64(&workingCount, 1)
				workingServers = append(workingServers, result)
				statusTags := []string{}
				if result.hasEDNS {
					statusTags = append(statusTags, "EDNS")
				}
				if result.dnsttCompatible {
					statusTags = append(statusTags, "DNSTT")
				}
				if result.hasTunnelResponse {
					statusTags = append(statusTags, "TUNNEL")
				}
				statusStr := ""
				if len(statusTags) > 0 {
					statusStr = " [" + strings.Join(statusTags, ",") + "]"
				}
				fmt.Printf("✓ %s (latency: %v)%s\n", result.ip, result.latency, statusStr)
			} else if verbose {
				fmt.Fprintf(os.Stderr, "✗ %s: %s\n", result.ip, result.errorMsg)
			}
			resultMutex.Unlock()

			progressInterval := totalIPs / 10
			if progressInterval > 1000 {
				progressInterval = 1000
			}
			if progressInterval > 0 && current%int64(progressInterval) == 0 {
				fmt.Fprintf(os.Stderr, "Progress: %d/%d (%.1f%%) - Found: %d\n",
					current, totalIPs, float64(current)*100/float64(totalIPs),
					atomic.LoadInt64(&workingCount))
			}
		}
	}()

	go func() {
		defer close(ipChan)
		for _, ip := range ips {
			select {
			case <-ctx.Done():
				return
			case ipChan <- ip:
			}
		}
	}()

	wg.Wait()
	close(results)
	resultWg.Wait()

	resultMutex.Lock()
	finalScanned := atomic.LoadInt64(&scanned)
	fmt.Fprintf(os.Stderr, "\n=== Scan Complete ===\n")
	fmt.Fprintf(os.Stderr, "Total IPs scanned: %d/%d\n", finalScanned, totalIPs)
	fmt.Fprintf(os.Stderr, "Working DNS servers: %d\n", len(workingServers))

	ednsCount := 0
	dnsttCount := 0
	tunnelRespCount := 0
	for _, r := range workingServers {
		if r.hasEDNS {
			ednsCount++
		}
		if r.dnsttCompatible {
			dnsttCount++
		}
		if r.hasTunnelResponse {
			tunnelRespCount++
		}
	}
	if len(workingServers) > 0 {
		fmt.Fprintf(os.Stderr, "With EDNS(0) support: %d\n", ednsCount)
		fmt.Fprintf(os.Stderr, "With DNSTT encoding support: %d\n", dnsttCount)
		fmt.Fprintf(os.Stderr, "With tunnel server response: %d\n\n", tunnelRespCount)
	} else {
		fmt.Fprintf(os.Stderr, "\n")
	}

	var output strings.Builder
	fmt.Fprintf(&output, "# DNS Scanner Results\n")
	fmt.Fprintf(&output, "# Scan Date: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&output, "# Input: %s\n", ipsInput)
	fmt.Fprintf(&output, "# Domain: %s\n", flag.Arg(0))
	fmt.Fprintf(&output, "# Total IPs scanned: %d/%d\n", finalScanned, totalIPs)
	fmt.Fprintf(&output, "# Working DNS servers: %d\n", len(workingServers))
	if len(workingServers) > 0 {
		outputEdnsCount := 0
		outputDnsttCount := 0
		outputTunnelRespCount := 0
		for _, r := range workingServers {
			if r.hasEDNS {
				outputEdnsCount++
			}
			if r.dnsttCompatible {
				outputDnsttCount++
			}
			if r.hasTunnelResponse {
				outputTunnelRespCount++
			}
		}
		fmt.Fprintf(&output, "# With EDNS(0) support: %d\n", outputEdnsCount)
		fmt.Fprintf(&output, "# With DNSTT encoding support: %d\n", outputDnsttCount)
		fmt.Fprintf(&output, "# With tunnel server response: %d\n", outputTunnelRespCount)
	}
	output.WriteString("\n")

	if len(workingServers) > 0 {
		output.WriteString("# Working DNS servers (use with -udp option):\n\n")
		for _, result := range workingServers {
			warnings := []string{}
			if !result.hasTunnelResponse {
				warnings = append(warnings, "No tunnel")
			}
			if !result.hasEDNS {
				warnings = append(warnings, "No EDNS support")
			}
			if !result.dnsttCompatible {
				warnings = append(warnings, "DNSTT encoding test failed")
			}
			warningNote := ""
			if len(warnings) > 0 {
				warningNote = "  # Warning: " + strings.Join(warnings, ", ")
			}
			fmt.Fprintf(&output, "./dnstt-client -udp %s:53 -pubkey-file server.pub %s 127.0.0.1:7000%s\n",
				result.ip, flag.Arg(0), warningNote)
		}
		output.WriteString("\n")
		output.WriteString("# IP addresses only (one per line):\n")
		for _, result := range workingServers {
			fmt.Fprintf(&output, "%s\n", result.ip)
		}
	} else {
		fmt.Fprintf(&output, "# No working DNS servers found\n")
	}

	if len(workingServers) > 0 {
		fmt.Println("Working DNS servers (use with -udp option):")
		for _, result := range workingServers {
			warnings := []string{}
			if !result.hasTunnelResponse {
				warnings = append(warnings, "No tunnel")
			}
			if !result.hasEDNS {
				warnings = append(warnings, "No EDNS support")
			}
			if !result.dnsttCompatible {
				warnings = append(warnings, "DNSTT encoding test failed")
			}
			warningNote := ""
			if len(warnings) > 0 {
				warningNote = "  # Warning: " + strings.Join(warnings, ", ")
			}
			fmt.Printf("  ./dnstt-client -udp %s:53 -pubkey-file server.pub %s 127.0.0.1:7000%s\n",
				result.ip, flag.Arg(0), warningNote)
		}
	} else {
		fmt.Fprintf(os.Stderr, "No working DNS servers found\n")
	}

	if outputFile != "" {
		err := os.WriteFile(outputFile, []byte(output.String()), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to write results to %s: %v\n", outputFile, err)
		} else {
			fmt.Fprintf(os.Stderr, "Results saved to: %s\n", outputFile)
		}
	}

	resultMutex.Unlock()
}
