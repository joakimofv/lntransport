package test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"math/rand"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/joakimofv/lntransport"
)

var benchmarkMsg []byte

func init() {
	// Prepare a large random message.
	benchmarkMsg = make([]byte, math.MaxUint16)
	rng := rand.New(rand.NewSource(1))
	rng.Read(benchmarkMsg)
}

func privkeyFixedSize(b []byte) (arr [32]byte) {
	copy(arr[:], b)
	return arr
}

func connect(t *testing.B) (c1, c2 *lntransport.Conn, ci1, ci2 net.Conn, closefn func()) {
	privkey1, _ := btcec.NewPrivateKey()
	lt1, _ := lntransport.New(lntransport.Config{Privkey: privkeyFixedSize(privkey1.Serialize())})
	privkey2, _ := btcec.NewPrivateKey()
	lt2, _ := lntransport.New(lntransport.Config{Privkey: privkeyFixedSize(privkey2.Serialize())})
	// Listen
	ch, addr, _ := lt1.Listen(context.Background(), "localhost:0")
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
		// Forward the connection to the LnTransport listener to make the handshake.
		ci1, err = net.Dial("tcp", addr.String())
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
	c2, _ = lt2.Dial(context.Background(), l.Addr().String(), privkey1.PubKey().SerializeCompressed())
	// The listener gets a conn.
	c1 = <-ch
	// Send and receive the first message, allocing the initial memory.
	if err := c1.Send(context.Background(), benchmarkMsg); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Receive(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Now stop forwarding the connection.
	if err := ci1.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := ci2.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	wg.Wait()

	closefn = func() {
		lt1.Close()
		lt2.Close()
	}
	return
}

func BenchmarkConn(t *testing.B) {
	c1, c2, ci1, ci2, closefn := connect(t)
	defer c1.Close()
	defer c2.Close()
	defer ci1.Close()
	defer ci2.Close()
	defer closefn()

	// We'll use a file to drain the data sent from c1 (intercepted by ci1).
	dir := os.Getenv("GOTEST_TMPDIR")
	f, err := os.CreateTemp(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closed := false
	// Write to the file in a goroutine. Cancel the send if there is an error.
	wg := new(sync.WaitGroup)
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
	t.Run("Send", func(t *testing.B) {
		t.ReportAllocs()
		for i := 0; i < t.N; i++ {
			if err := c1.Send(ctx, benchmarkMsg); err != nil {
				t.Fatal(err)
			}
		}
	})
	since := time.Since(now)
	// Generate more data so that it will be sufficient for the use by the receiver benchmark.
	ctx, cancel = context.WithTimeout(ctx, since)
	defer cancel()
	for {
		if err := c1.Send(ctx, benchmarkMsg); err != nil {
			if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
				t.Log(err)
			}
			break
		}
	}
	cancel()

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
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
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

	t.Run("Receive", func(t *testing.B) {
		t.ReportAllocs()
		for i := 0; i < t.N; i++ {
			if _, err := c2.Receive(ctx); err != nil {
				t.Fatal(err)
			}
		}
	})
	cancel()
	closed = true
}

func BenchmarkBase(t *testing.B) {
	c1, c2, ci1, ci2, closefn := connect(t)
	defer c1.Close()
	defer c2.Close()
	defer ci1.Close()
	defer ci2.Close()
	defer closefn()

	// Get one encoded message from c1/ci1 that we will use for the rest of the benchmark.
	buf := new(bytes.Buffer)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closed := false
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := ci1.SetReadDeadline(time.Time{}); err != nil {
			t.Error(err)
			cancel()
			return
		}
		if _, err := io.Copy(buf, ci1); err != nil {
			if !closed {
				t.Error(err)
			}
			cancel()
			return
		}
	}()
	if err := c1.Send(ctx, benchmarkMsg); err != nil {
		t.Fatal(err)
	}
	closed = true
	c1.Close() // Interrupts the io.Copy by making ci1 get EOF.
	wg.Wait()
	encodedBenchmarkMsg := buf.Bytes()
	t.Logf("encoded message is %vKB", len(encodedBenchmarkMsg)/(1024))

	// Now stop using the existing connections, create new ones that don't do any encryption/decryption.
	var c3, c4, ci3, ci4 net.Conn
	l3, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l3.Close()
	l4, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l4.Close()
	go func() {
		var err error
		c3, err = net.Dial("tcp", l3.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		ci4, err = net.Dial("tcp", l4.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
	}()
	ci3, err = l3.Accept()
	if err != nil {
		t.Fatal(err)
	}
	c4, err = l4.Accept()
	if err != nil {
		t.Fatal(err)
	}

	// We'll use a file to drain the data sent from c3 (intercepted by ci3).
	// Note: this code block must be the same as in BenchmarkConn.
	f, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	cancel = func() {
		c3.SetDeadline(time.Now())
	}
	closed = false
	// Write to the file in a goroutine. Cancel the send if there is an error.
	wg = new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		defer wg.Done()
		w := bufio.NewWriter(f)
		if err := ci3.SetReadDeadline(time.Time{}); err != nil {
			t.Error(err)
			cancel()
			return
		}
		if _, err := io.Copy(w, ci3); err != nil {
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

	// Write the same data into c3 again and again, the simplest/fastest possible kind of send.
	now := time.Now()
	t.Run("Write", func(t *testing.B) {
		t.ReportAllocs()
		for i := 0; i < t.N; i++ {
			if _, err := c3.Write(encodedBenchmarkMsg); err != nil {
				t.Fatal(err)
			}
		}
	})
	since := time.Since(now)
	// Generate more data so that it will be sufficient for the use by the receiver benchmark.
	timer := time.AfterFunc(since, func() {
		c3.SetDeadline(time.Now())
	})
	for {
		if _, err := c3.Write(encodedBenchmarkMsg); err != nil {
			if !err.(net.Error).Timeout() {
				t.Log(err)
			}
			break
		}
	}
	timer.Stop()

	// Flush the data to file.
	closed = true
	c3.Close() // Interrupts the io.Copy by making ci3 get EOF.
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

	// Feed the data from file to be received at c4 (through ci4).
	f, err = os.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cancel = func() {
		c4.SetDeadline(time.Now())
	}
	closed = false
	// Read from the file in a goroutine. Cancel the receive if there is an error.
	go func() {
		r := bufio.NewReader(f)
		if _, err := io.CopyN(ci4, r, stat.Size()); err != nil {
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
			if _, err := c4.Read(msg); err != nil {
				t.Fatal(err)
			}
		}
	})
	closed = true
}
