package socks5

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"context"
	"sync"
	"testing"
	"time"

	ssock "github.com/txthinking/socks5"
)

func TestSOCKS5_Associate(t *testing.T) {
	// Create a udp listener
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:8888")
	l, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer l.Close()
	go func() {
		defer l.Close()
		var buf [1024]byte
		for {
			n, from, err := l.ReadFromUDP(buf[:])
			if err != nil {
				t.Fatalf("err: %v", err)
				break
			}
			if i := bytes.Index(buf[:n], []byte("ping")); i == -1 {
				t.Fatalf("bad: %v", buf)
			} else {
				idx, _ := strconv.Atoi(string(buf[4:n]))
				msg := fmt.Sprintf("pong%v", idx)
				fmt.Printf("@@@ response udp read %v, echo %v @@@\n", string(buf[:n]), msg)
				l.WriteToUDP([]byte(msg), from)
			}
		}
	}()

	// Create a socks server
	creds := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: creds}
	conf := &Config{
		AuthMethods: []Authenticator{cator},
		BindIP:      net.ParseIP("127.0.0.1"),
		Logger:      log.New(os.Stdout, "", log.LstdFlags),
	}
	serv, err := New(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Start listening on TCP port 12366
	_, cancel := context.WithCancel(context.Background())
	go func() {
		if err := serv.ListenAndServe("tcp", "127.0.0.1:12366"); err != nil {
			t.Errorf("Error starting SOCKS5 server: %v", err)
		}
	}()
	time.Sleep(10 * time.Millisecond)

	// 10 task
	n := 10
	var wg = sync.WaitGroup{}
	for ; n > 0; n-- {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			s5, err := ssock.NewClient("127.0.0.1:12366", "foo", "bar", 0, 0)
			if err != nil {
				t.Fatalf("NewClient err: %v", err)
				return
			}
			conn, err := s5.Dial("udp", "local.cloudpc.cn:8888")
			if err != nil {
				t.Fatalf("NewClient err: %v", err)
				return
			}
			defer conn.Close()

			var buf [1024]byte
			msg := fmt.Sprintf("ping%v", i)
			_, err = conn.Write([]byte(msg))
			if err != nil {
				t.Fatalf("conn.Write err: %v", err)
				return
			}
			l, err := conn.Read(buf[:])
			fmt.Printf("### response len %v: %v ###\n", l, string(buf[:l]))
		}(n)
	}
	wg.Wait()

	// Signal the server to stop listening and ensure the test completes
	cancel()
}