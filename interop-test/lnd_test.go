package test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningnetwork/lnd/brontide"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tor"

	"github.com/joakimofv/lntransport"
)

// TestWithLnd tests lntransport against code in github.com/lightningnetwork/lnd/brontide.
func TestWithLnd(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	lt, err := lntransport.New(lntransport.Config{Privkey: privkeyFixedSize(privkey.Serialize())})
	if err != nil {
		t.Fatal(err)
	}
	defer lt.Close()

	lndPrivkey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	lndKeyECDH := &keychain.PrivKeyECDH{PrivKey: lndPrivkey}

	msg := make([]byte, math.MaxUint16)

	t.Run("Listen", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ch, addr, err := lt.Listen(ctx, "localhost:0")
		if err != nil {
			t.Fatal(err)
		}
		netAddr := &lnwire.NetAddress{
			IdentityKey: privkey.PubKey(),
			Address:     net.TCPAddrFromAddrPort(addr),
		}

		// Dial from lnd/brontide.
		lndConn, err := brontide.Dial(
			lndKeyECDH, netAddr,
			tor.DefaultConnTimeout, net.DialTimeout,
		)
		if err != nil {
			t.Fatal(err)
		}
		defer lndConn.Close()

		var conn *lntransport.Conn
		select {
		case conn = <-ch:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for connection")
		}
		defer conn.Close()

		// Send a message.
		if _, err := lndConn.Write(msg); err != nil {
			t.Fatal(err)
		}
		ctx, cancel = context.WithTimeout(ctx, time.Second)
		defer cancel()
		if msg2, err := conn.Receive(ctx); err != nil {
			t.Error(err)
		} else if !bytes.Equal(msg, msg2) {
			t.Error("message contents changed")
		}
	})

	t.Run("Dial", func(t *testing.T) {
		// Listen from lnd/brontide.
		lndListener, err := brontide.NewListener(lndKeyECDH, "localhost:0")
		if err != nil {
			t.Fatal(err)
		}
		defer lndListener.Close()

		// Dial from us.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, err := lt.Dial(ctx, lndListener.Addr().String(), lndPrivkey.PubKey().SerializeCompressed())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		go func() {
			<-time.After(time.Second)
			lndListener.Close()
		}()
		lndConn, err := lndListener.Accept()
		if err != nil {
			t.Fatal(err)
		}

		// Send a message.
		if err = conn.Send(ctx, msg); err != nil {
			t.Fatal(err)
		}
		if err := lndConn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		msg2 := bytes.Repeat([]byte("a"), math.MaxUint16)
		if _, err := lndConn.Read(msg2); err != nil {
			t.Error(err)
		} else if !bytes.Equal(msg, msg2) {
			t.Error("message contents changed")
		}
	})
}

func FuzzWithLndSend(f *testing.F) {
	testcases := []string{"Hello, world", " ", "!12345", ""}
	for _, tc := range testcases {
		f.Add([]byte(tc))
	}
	privkey, err := btcec.NewPrivateKey()
	if err != nil {
		f.Fatal(err)
	}
	lt, err := lntransport.New(lntransport.Config{Privkey: privkeyFixedSize(privkey.Serialize())})
	if err != nil {
		f.Fatal(err)
	}
	defer lt.Close()
	lndPrivkey, err := btcec.NewPrivateKey()
	if err != nil {
		f.Fatal(err)
	}
	lndKeyECDH := &keychain.PrivKeyECDH{PrivKey: lndPrivkey}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, addr, err := lt.Listen(ctx, "localhost:0")
	if err != nil {
		f.Fatal(err)
	}
	netAddr := &lnwire.NetAddress{
		IdentityKey: privkey.PubKey(),
		Address:     net.TCPAddrFromAddrPort(addr),
	}
	// Dial from lnd/brontide.
	lndConn, err := brontide.Dial(
		lndKeyECDH, netAddr,
		tor.DefaultConnTimeout, net.DialTimeout,
	)
	if err != nil {
		f.Fatal(err)
	}
	defer lndConn.Close()
	var conn *lntransport.Conn
	select {
	case conn = <-ch:
	case <-time.After(time.Second):
		f.Fatal("timed out waiting for connection")
	}
	defer conn.Close()

	f.Fuzz(func(t *testing.T, msg []byte) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err = conn.Send(ctx, msg); err != nil {
			if err == lntransport.ErrMaxMessageLengthExceeded && len(msg) > math.MaxUint16 {
				return
			}
			t.Fatal(err)
		}
		if err := lndConn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		msg2 := make([]byte, math.MaxUint16)
		if n, err := lndConn.Read(msg2); err != nil {
			if len(msg) == 0 {
				// LND can't handle this, continue fuzzing anyway, can't fix their problems.
				return
			}
			t.Error(err)
		} else if !bytes.Equal(msg, msg2[:n]) {
			t.Error("message contents changed")
		}
	})
}

func FuzzWithLndReceive(f *testing.F) {
	testcases := []string{"Hello, world", " ", "!12345", ""}
	for _, tc := range testcases {
		f.Add([]byte(tc))
	}
	privkey, err := btcec.NewPrivateKey()
	if err != nil {
		f.Fatal(err)
	}
	lt, err := lntransport.New(lntransport.Config{Privkey: privkeyFixedSize(privkey.Serialize())})
	if err != nil {
		f.Fatal(err)
	}
	defer lt.Close()
	lndPrivkey, err := btcec.NewPrivateKey()
	if err != nil {
		f.Fatal(err)
	}
	lndKeyECDH := &keychain.PrivKeyECDH{PrivKey: lndPrivkey}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, addr, err := lt.Listen(ctx, "localhost:0")
	if err != nil {
		f.Fatal(err)
	}
	netAddr := &lnwire.NetAddress{
		IdentityKey: privkey.PubKey(),
		Address:     net.TCPAddrFromAddrPort(addr),
	}
	// Dial from lnd/brontide.
	lndConn, err := brontide.Dial(
		lndKeyECDH, netAddr,
		tor.DefaultConnTimeout, net.DialTimeout,
	)
	if err != nil {
		f.Fatal(err)
	}
	defer lndConn.Close()
	var conn *lntransport.Conn
	select {
	case conn = <-ch:
	case <-time.After(time.Second):
		f.Fatal("timed out waiting for connection")
	}
	defer conn.Close()

	f.Fuzz(func(t *testing.T, msg []byte) {
		if _, err := lndConn.Write(msg); err != nil {
			if len(msg) > math.MaxUint16 {
				return
			}
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if msg2, err := conn.Receive(ctx); err != nil {
			t.Error(err)
		} else if !bytes.Equal(msg, msg2) {
			t.Error("message contents changed")
		}
	})
}

func BenchmarkLnd(t *testing.B) {
	var c1, c2 *brontide.Conn
	var ci1, ci2 net.Conn

	privkey1, _ := btcec.NewPrivateKey()
	privkey2, _ := btcec.NewPrivateKey()
	lndKeyECDH1 := &keychain.PrivKeyECDH{PrivKey: privkey1}
	lndKeyECDH2 := &keychain.PrivKeyECDH{PrivKey: privkey2}
	// Listen
	lndListener, err := brontide.NewListener(lndKeyECDH2, "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lndListener.Close()
	// Intercept
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		ci2, err = l.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		// Forward the connection to the lndListener to make the handshake.
		ci1, err = net.Dial("tcp", lndListener.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := io.Copy(ci1, ci2); err != nil && !err.(net.Error).Timeout() {
				t.Error(err)
			}
		}()
		if _, err := io.Copy(ci2, ci1); err != nil && !err.(net.Error).Timeout() {
			t.Error(err)
		}
	}()
	// Dial
	netAddr := &lnwire.NetAddress{
		IdentityKey: privkey2.PubKey(),
		Address:     l.Addr().(*net.TCPAddr),
	}
	c2, err = brontide.Dial(
		lndKeyECDH1, netAddr,
		tor.DefaultConnTimeout, net.DialTimeout,
	)
	if err != nil {
		t.Fatal(err)
	}
	// The listener gets a conn.
	c1net, err := lndListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	c1 = c1net.(*brontide.Conn)
	// Now stop forwarding the connection.
	if err := ci1.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := ci2.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	wg.Wait()

	defer c1.Close()
	defer c2.Close()
	defer ci1.Close()
	defer ci2.Close()

	// We'll use a file to drain the data sent from c1 (intercepted by ci1).
	// Note: this code block must be the same as in BenchmarkConn.
	f, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	cancel := func() {
		c1.SetDeadline(time.Now())
	}
	closed := false
	// Write to the file in a goroutine. Cancel the send if there is an error.
	wg = new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		defer wg.Done()
		w := bufio.NewWriter(f)
		if err := ci1.SetReadDeadline(time.Time{}); err != nil {
			t.Error(err)
			cancel()
			return
		}
		if _, err := io.Copy(w, ci1); err != nil {
			// This check only works on Linux.
			if errors.Is(err, syscall.ENOSPC) {
				// Out of disk space, it is fine, hope that the file is big enough.
				t.Log(err)
			} else if !closed {
				t.Error(err)
			}
			cancel()
			return
		}
		if err := w.Flush(); err != nil {
			t.Error(err)
			cancel()
			return
		}
	}()

	// Generate encoded data, benchmark it.
	now := time.Now()
	t.Run("Write", func(t *testing.B) {
		t.ReportAllocs()
		for i := 0; i < t.N; i++ {
			if _, err := c1.Write(benchmarkMsg); err != nil {
				t.Fatal(err)
			}
		}
	})
	since := time.Since(now)
	// Generate more data so that it will be sufficient for the use by the receiver benchmark.
	timer := time.AfterFunc(since, func() {
		c1.SetDeadline(time.Now())
	})
	for {
		if _, err := c1.Write(benchmarkMsg); err != nil {
			if !err.(net.Error).Timeout() {
				t.Log(err)
			}
			break
		}
	}
	timer.Stop()

	// Flush the data to file.
	closed = true
	c1.Close() // Interrupts the io.Copy by making ci1 get EOF.
	wg.Wait()
	// Inspect the file.
	stat, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("saved %vMB encrypted data", stat.Size()/(1024*1024))
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// Feed the data from file to be received at c2 (through ci2).
	f, err = os.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cancel = func() {
		c2.SetDeadline(time.Now())
	}
	closed = false
	// Read from the file in a goroutine. Cancel the receive if there is an error.
	go func() {
		r := bufio.NewReader(f)
		if _, err := io.CopyN(ci2, r, stat.Size()); err != nil {
			if !closed {
				t.Error(err)
			}
		} else {
			// Having the full copy go through means the receive runs out of data to work on, it will block waiting, have to fail.
			t.Error("out of data")
		}
		cancel()
	}()

	msg := make([]byte, math.MaxUint32)
	t.Run("Read", func(t *testing.B) {
		t.ReportAllocs()
		for i := 0; i < t.N; i++ {
			if _, err := c2.Read(msg); err != nil {
				t.Fatal(err)
			}
		}
	})
	closed = true
}
