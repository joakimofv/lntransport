package lntransport

import (
	"bytes"
	"context"
	"errors"
	"log"
	"math"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func init() {
	log.SetFlags(log.Lmicroseconds | log.Lshortfile)
}

func privkeyFixedSize(b []byte) (arr [32]byte) {
	copy(arr[:], b)
	return arr
}

func TestBadPrivkey(t *testing.T) {
	// Make sure we clean.
	fdsBefore := fileDescriptorCount(t)
	defer t.Run("fdcount", func(t *testing.T) {
		fdsAfter := fileDescriptorCount(t)
		if fdsBefore != fdsAfter {
			t.Errorf("file descriptors count expected %v, got %v", fdsBefore, fdsAfter)
		}
	})

	lt, err := New(Config{})
	if err == nil {
		t.Fatal("expected invalid Privkey error")
	}
	if lt != nil {
		t.Fatal("expected nil")
	}
}

func TestListen(t *testing.T) {
	// Make sure we clean.
	fdsBefore := fileDescriptorCount(t)
	defer t.Run("fdcount", func(t *testing.T) {
		fdsAfter := fileDescriptorCount(t)
		if fdsBefore != fdsAfter {
			t.Errorf("file descriptors count expected %v, got %v", fdsBefore, fdsAfter)
		}
	})

	privkey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	lt, err := New(Config{Privkey: privkeyFixedSize(privkey.Serialize())})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	ch, addr, err := lt.Listen(ctx, "127.0.0.1:12345")
	if err != nil {
		t.Fatal(err)
	}

	if addr != netip.MustParseAddrPort("127.0.0.1:12345") {
		t.Errorf("%v != %v", addr, netip.MustParseAddrPort("127.0.0.1:12345"))
	}

	select {
	case c, ok := <-ch:
		t.Fatal("unexpected signal", c, ok)
	case <-time.After(10 * time.Millisecond):
	}
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("channel not closed after context cancel")
		}
	case <-time.After(10 * time.Millisecond):
		t.Fatal("channel not closed after context cancel")
	}

	if err := lt.Close(); err != nil {
		t.Error(err)
	}
	// A call after close gives error.
	if _, _, err = lt.Listen(context.Background(), "localhost:0"); err != ErrLnTransportClosed {
		t.Error(err)
	}
}

func TestBadListen(t *testing.T) {
	// Make sure we clean.
	fdsBefore := fileDescriptorCount(t)
	defer t.Run("fdcount", func(t *testing.T) {
		fdsAfter := fileDescriptorCount(t)
		if fdsBefore != fdsAfter {
			t.Errorf("file descriptors count expected %v, got %v", fdsBefore, fdsAfter)
		}
	})

	privkey, _ := btcec.NewPrivateKey()
	lt, _ := New(Config{Privkey: privkeyFixedSize(privkey.Serialize())})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, _, err := lt.Listen(ctx, "ysdfuhreiu")
	if err == nil {
		t.Fatal("expected error")
	}

	if err := lt.Close(); err != nil {
		t.Error(err)
	}
}

func TestDial(t *testing.T) {
	// Make sure we clean.
	fdsBefore := fileDescriptorCount(t)
	defer t.Run("fdcount", func(t *testing.T) {
		fdsAfter := fileDescriptorCount(t)
		if fdsBefore != fdsAfter {
			t.Errorf("file descriptors count expected %v, got %v", fdsBefore, fdsAfter)
		}
	})

	privkey1, _ := btcec.NewPrivateKey()
	lt1, _ := New(Config{Privkey: privkeyFixedSize(privkey1.Serialize())})
	privkey2, _ := btcec.NewPrivateKey()
	lt2, _ := New(Config{Privkey: privkeyFixedSize(privkey2.Serialize())})

	// Listen
	ch, addr, err := lt1.Listen(context.Background(), "localhost:0")
	if err != nil {
		t.Fatal(err)
	}

	// Dial
	ctx, cancel := context.WithCancel(context.Background())
	c2, err := lt2.Dial(ctx, addr.String(), privkey1.PubKey().SerializeCompressed())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	cancel() // Doesn't destroy the Conn after the Dial is complete.

	// Check the public functions of the Conn.
	if c2.IsClosed() {
		t.Error("conn closed")
	}
	t.Log(c2.LocalAddrPort()) // Port randomly selected, no way to assert on it.
	array := c2.LocalPubkey()
	if localpub2, err := secp256k1.ParsePubKey(array[:]); err != nil {
		t.Error(err)
	} else if !localpub2.IsEqual(privkey2.PubKey()) {
		t.Error(localpub2, privkey2.PubKey())
	}
	if c2.RemoteAddrPort() != addr {
		t.Errorf("%v != %v", c2.RemoteAddrPort(), addr)
	}
	array = c2.RemotePubkey()
	if remotepub2, err := secp256k1.ParsePubKey(array[:]); err != nil {
		t.Error(err)
	} else if !remotepub2.IsEqual(privkey1.PubKey()) {
		t.Error(remotepub2, privkey1.PubKey())
	}

	// The listener gets a conn.
	select {
	case c1, ok := <-ch:
		if !ok {
			t.Error("Listen channel closed")
			break
		}
		defer c1.Close()
		// Check the public functions of the Conn.
		if c1.IsClosed() {
			t.Error("conn closed")
		}
		if c1.LocalAddrPort() != addr {
			t.Errorf("%v != %v", c1.LocalAddrPort(), addr)
		}
		array := c1.LocalPubkey()
		if localpub1, err := secp256k1.ParsePubKey(array[:]); err != nil {
			t.Error(err)
		} else if !localpub1.IsEqual(privkey1.PubKey()) {
			t.Error(localpub1, privkey1.PubKey())
		}
		if c1.RemoteAddrPort() != c2.LocalAddrPort() {
			t.Errorf("%v != %v", c1.RemoteAddrPort(), c2.LocalAddrPort())
		}
		array = c1.RemotePubkey()
		if remotepub1, err := secp256k1.ParsePubKey(array[:]); err != nil {
			t.Error(err)
		} else if !remotepub1.IsEqual(privkey2.PubKey()) {
			t.Error(remotepub1, privkey2.PubKey())
		}
	case <-time.After(10 * time.Millisecond):
		t.Fatal("No Conn on Listen channel")
	}

	// Another call goes through too.
	c3, err := lt2.Dial(context.Background(), addr.String(), privkey1.PubKey().SerializeCompressed())
	if err != nil {
		t.Error(err)
	}
	defer c3.Close()
	// Take the conn from the listener so that the thread finishes.
	c4 := <-ch
	defer c4.Close()
	// Both connections are open (even though they are duplicates, we allow that).
	if c2.IsClosed() || c3.IsClosed() {
		t.Error(c2.IsClosed(), c3.IsClosed())
	}

	// Close the listener side.
	if err := lt1.Close(); err != nil {
		t.Error(err)
	}
	// A dial to a closed listener gives error.
	if _, err := lt2.Dial(context.Background(), addr.String(), privkey1.PubKey().SerializeCompressed()); err == nil {
		t.Error("expected connection refused error, got nil")
	} else {
		t.Logf("[%T] %[1]v", err)
	}

	// Close the dialer side.
	if err := lt2.Close(); err != nil {
		t.Error(err)
	}
	// A call after close gives error.
	if _, err = lt2.Dial(context.Background(), addr.String(), privkey1.PubKey().SerializeCompressed()); err != ErrLnTransportClosed {
		t.Error(err)
	}
}

func TestListenErr(t *testing.T) {
	// Make sure we clean.
	fdsBefore := fileDescriptorCount(t)
	defer t.Run("fdcount", func(t *testing.T) {
		fdsAfter := fileDescriptorCount(t)
		if fdsBefore != fdsAfter {
			t.Errorf("file descriptors count expected %v, got %v", fdsBefore, fdsAfter)
		}
	})

	privkey1, _ := btcec.NewPrivateKey()
	errCh := make(chan ErrAndAddrPort, 1)
	var errFuncErr ErrAndAddrPort
	lt1, _ := New(Config{
		Privkey:        privkeyFixedSize(privkey1.Serialize()),
		ListenErrNoLog: true,
		ListenErrChan:  errCh,
		ListenErrFunc: func(ea ErrAndAddrPort) {
			errFuncErr = ea
		},
	})
	defer lt1.Close()
	privkey2, _ := btcec.NewPrivateKey()
	lt2, _ := New(Config{Privkey: privkeyFixedSize(privkey2.Serialize())})
	defer lt2.Close()

	// Listen
	_, addr, err := lt1.Listen(context.Background(), "localhost:0")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.ValueOf(errFuncErr).IsZero() {
		t.Error(errFuncErr)
	}

	// Dial with the wrong pubkey
	_, err = lt2.Dial(context.Background(), addr.String(), privkey2.PubKey().SerializeCompressed())
	if err == nil {
		t.Fatal("expected error")
	}

	// Expecting AuthError from listener.
	// On channel.
	var ea ErrAndAddrPort
	select {
	case ea = <-errCh:
		if ea.AddrPort != addr {
			t.Errorf("expected %v, got %v", addr, ea.AddrPort)
		}
		var authErr AuthError
		if !errors.As(ea.Err, &authErr) {
			t.Errorf("unexpected error type %T: %[1]v", ea.Err)
		} else {
			// Don't know the auto selected addrPort, just check non-zero.
			if authErr.RemoteAddrPort == (netip.AddrPort{}) {
				t.Error("zero RemoteAddrPort")
			}
		}
	case <-time.After(time.Millisecond):
		t.Fatal("timed out waiting for listener error")
	}
	// On function.
	if ea != errFuncErr {
		t.Errorf("expected %v, got %v", ea, errFuncErr)
	}
}

func TestSendReceive(t *testing.T) {
	// Make sure we clean.
	fdsBefore := fileDescriptorCount(t)
	defer t.Run("fdcount", func(t *testing.T) {
		fdsAfter := fileDescriptorCount(t)
		if fdsBefore != fdsAfter {
			t.Errorf("file descriptors count expected %v, got %v", fdsBefore, fdsAfter)
		}
	})

	privkey1, _ := btcec.NewPrivateKey()
	lt1, _ := New(Config{Privkey: privkeyFixedSize(privkey1.Serialize())})
	privkey2, _ := btcec.NewPrivateKey()
	lt2, _ := New(Config{Privkey: privkeyFixedSize(privkey2.Serialize())})

	// Listen
	ch, addr, _ := lt1.Listen(context.Background(), "localhost:0")

	// Dial
	c2, _ := lt2.Dial(context.Background(), addr.String(), privkey1.PubKey().SerializeCompressed())

	// The listener gets a conn.
	c1 := <-ch

	// Send from dialer, receive at listener.
	msg := []byte("sufdfuesufiui")
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	if err := c2.Send(ctx1, msg); err != nil {
		t.Error(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	msg2, err := c1.Receive(ctx2)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(msg, msg2) {
		t.Errorf("%s != %s", msg, msg2)
	}

	// Send from listener, receive at dialer.
	msg3 := []byte("hjkyyjtrrrrt")
	ctx3, cancel3 := context.WithCancel(context.Background())
	if err := c1.Send(ctx3, msg3); err != nil {
		t.Error(err)
	}
	ctx4, cancel4 := context.WithCancel(context.Background())
	msg4, err := c2.Receive(ctx4)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(msg3, msg4) {
		t.Errorf("%s != %s", msg3, msg4)
	}

	// Try to send around max message length, succeed or fail with ErrMaxMessageLengthExceeded.
	ctx5, cancel5 := context.WithCancel(context.Background())
	if err := c2.Send(ctx5, make([]byte, math.MaxUint16)); err != nil {
		t.Error(err)
	}
	if err := c2.Send(context.Background(), make([]byte, math.MaxUint16+1)); err != ErrMaxMessageLengthExceeded {
		t.Error(err)
	}

	// Cancel the contexts in anticipation of the contextWatcher check.
	//cancel1() // Superceded by the the second  c2.Send
	cancel2()
	cancel3()
	cancel4()
	cancel5()
	time.Sleep(1 * time.Millisecond)

	// contextWatcher should be emptied of select cases when the contexts expired.
	t.Run("contextWatcher", func(t *testing.T) {
		if len(lt1.cases) > 2 {
			t.Error(len(lt1.cases))
		}
		if len(lt2.cases) > 2 {
			t.Error(len(lt2.cases))
		}
	})

	if err := lt1.Close(); err != nil {
		t.Error(err)
	}
	if err := lt2.Close(); err != nil {
		t.Error(err)
	}
	if err := c1.Close(); err != nil {
		t.Error(err)
	}
	if err := c2.Close(); err != nil {
		t.Error(err)
	}
}

func FuzzSendReceive(f *testing.F) {
	testcases := []string{"Hello, world", " ", "!12345", ""}
	for _, tc := range testcases {
		f.Add([]byte(tc))
	}

	privkey1, _ := btcec.NewPrivateKey()
	lt1, _ := New(Config{Privkey: privkeyFixedSize(privkey1.Serialize())})
	defer lt1.Close()
	privkey2, _ := btcec.NewPrivateKey()
	lt2, _ := New(Config{Privkey: privkeyFixedSize(privkey2.Serialize())})
	defer lt2.Close()
	ch, addr, _ := lt1.Listen(context.Background(), "localhost:0")
	c2, _ := lt2.Dial(context.Background(), addr.String(), privkey1.PubKey().SerializeCompressed())
	defer c2.Close()
	c1 := <-ch
	defer c1.Close()

	f.Fuzz(func(t *testing.T, msg []byte) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := c1.Send(ctx, msg); err != nil {
			if err == ErrMaxMessageLengthExceeded && len(msg) > math.MaxUint16 {
				return
			}
			t.Fatal(err)
		}
		msg2, err := c2.Receive(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(msg, msg2) {
			t.Errorf("%s != %s", msg, msg2)
		}
	})
}
