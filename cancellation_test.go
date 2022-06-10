package lntransport

import (
	"bytes"
	"context"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

func TestCancellation(t *testing.T) {
	// Creating and closing a LnTransport shouldn't leave open file descriptors.
	fdsBefore := fileDescriptorCount(t)
	defer t.Run("fdcount", func(t *testing.T) {
		fdsAfter := fileDescriptorCount(t)
		if fdsBefore != fdsAfter {
			t.Errorf("file descriptors count expected %v, got %v", fdsBefore, fdsAfter)
		}
	})

	privkey1, _ := btcec.NewPrivateKey()
	lt1, _ := New(Config{Privkey: privkeyFixedSize(privkey1.Serialize())})
	defer lt1.Close()
	privkey2, _ := btcec.NewPrivateKey()
	lt2, _ := New(Config{Privkey: privkeyFixedSize(privkey2.Serialize())})
	defer lt2.Close()

	// contextWatcher should be emptied of select cases when the conns are closed.
	defer t.Run("contextWatcher", func(t *testing.T) {
		if len(lt1.cases) > 2 {
			t.Error(len(lt1.cases))
		}
		if len(lt2.cases) > 2 {
			t.Error(len(lt2.cases))
		}
	})

	// Creating and closing lots of listeners and connections shouldn't leave open file descriptors.
	fdsInnerBefore := fileDescriptorCount(t)
	defer t.Run("fdcountInner", func(t *testing.T) {
		fdsInnerAfter := fileDescriptorCount(t)
		if fdsInnerBefore != fdsInnerAfter {
			t.Errorf("file descriptors count expected %v, got %v", fdsInnerBefore, fdsInnerAfter)
		}
	})

	// Large message, so that it will take as long as possible to send.
	msg := make([]byte, math.MaxUint16)

	// Test cases run in parallel, but must be wrapped in a common test so that they will complete before the defers above.
	t.Run("tc", func(t *testing.T) {
		for name, tc := range map[string]struct {
			iterations int
			doClose    bool
			onSend     bool
			onReceive  bool
			waits      []time.Duration
		}{
			"cancel": {onSend: true, onReceive: true,
				iterations: 1, waits: []time.Duration{10 * time.Microsecond}},
			"cancel1000": {onSend: true, onReceive: true,
				iterations: 1000, waits: []time.Duration{1 * time.Microsecond, 10 * time.Microsecond, 20 * time.Microsecond, 30 * time.Microsecond, 40 * time.Microsecond, 50 * time.Microsecond, 60 * time.Microsecond, 70 * time.Microsecond, 80 * time.Microsecond, 90 * time.Microsecond, 100 * time.Microsecond}},
			// Would make the receive wait forever.
			//"cancelSend": {onSend: true,
			//	iterations: 10, waits: []time.Duration{1 * time.Microsecond, 10 * time.Microsecond, 100 * time.Microsecond}},
			"cancelReceive": {onReceive: true,
				iterations: 10, waits: []time.Duration{1 * time.Microsecond, 10 * time.Microsecond, 100 * time.Microsecond}},
			"close": {doClose: true, onSend: true, onReceive: true,
				iterations: 1, waits: []time.Duration{10 * time.Microsecond}},
			"close200": {doClose: true, onSend: true, onReceive: true,
				iterations: 200, waits: []time.Duration{1 * time.Microsecond, 10 * time.Microsecond, 20 * time.Microsecond, 30 * time.Microsecond, 40 * time.Microsecond, 50 * time.Microsecond, 60 * time.Microsecond, 70 * time.Microsecond, 80 * time.Microsecond, 90 * time.Microsecond, 100 * time.Microsecond}},
			"closeSend": {doClose: true, onSend: true,
				iterations: 10, waits: []time.Duration{1 * time.Microsecond, 10 * time.Microsecond, 100 * time.Microsecond}},
			"closeReceive": {doClose: true, onReceive: true,
				iterations: 10, waits: []time.Duration{1 * time.Microsecond, 10 * time.Microsecond, 100 * time.Microsecond}},
		} {
			tc := tc
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				// Create the Conn pair.
				ctxListen, cancelListen := context.WithCancel(context.Background())
				defer cancelListen()
				ch, addr, _ := lt1.Listen(ctxListen, "localhost:0")
				c2, _ := lt2.Dial(context.Background(), addr.String(), privkey1.PubKey().SerializeCompressed())
				c1 := <-ch
				defer func() {
					c1.Close()
					c2.Close()
				}()

				quit := make(chan struct{})
				errSendCh := make(chan error, 2)
				errReceiveCh := make(chan error, 2)

				// Sending goroutine.
				doSend := make(chan context.Context)
				anotherSend := make(chan context.Context)
				sender := func() {
					for {
						var ctx context.Context
						select {
						case ctx = <-doSend:
							anotherSend <- ctx
						case ctx = <-anotherSend:
						case <-quit:
							return
						}
						errSendCh <- c1.Send(ctx, msg)
					}
				}
				go sender()
				go sender()

				// Receiving goroutine.
				doReceive := make(chan context.Context)
				anotherReceive := make(chan context.Context)
				receiver := func() {
					for {
						var ctx context.Context
						select {
						case ctx = <-doReceive:
							anotherReceive <- ctx
						case ctx = <-anotherReceive:
						case <-quit:
							return
						}
						_, err := c2.Receive(ctx)
						errReceiveCh <- err
					}
				}
				go receiver()
				go receiver()

				var success, closed, closedAtEntry, recoverable int
				for i := 0; i < tc.iterations; i++ {
					sendCtx, sendCtxCancel := context.WithCancel(context.Background())
					defer sendCtxCancel()
					receiveCtx, receiveCtxCancel := context.WithCancel(context.Background())
					defer receiveCtxCancel()

					// Start the send/receive and then interrupt.
					doSend <- sendCtx
					doReceive <- receiveCtx
					// Randomize time until interrupt.
					time.Sleep(tc.waits[rand.Intn(len(tc.waits))])
					if tc.doClose {
						if tc.onSend {
							if err := c1.Close(); err != nil {
								t.Error(err)
							}
						}
						if tc.onReceive {
							if err := c2.Close(); err != nil {
								t.Error(err)
							}
						}
					} else {
						if tc.onSend {
							sendCtxCancel()
						}
						if tc.onReceive {
							receiveCtxCancel()
						}
					}

					var err1, err2, err3, err4 error
					s := 0
					r := 0
					for k := 0; k < 4; k++ {
						select {
						case err := <-errSendCh:
							switch s {
							case 0:
								s++
								err1 = err
							case 1:
								err3 = err
							}
						case err := <-errReceiveCh:
							switch r {
							case 0:
								r++
								err2 = err
							case 1:
								err4 = err
							}
						case <-time.After(time.Second):
							t.Fatal("interrupt failed (timed out waiting for function return)")
						}
					}
					if err1 == nil && err3 == nil {
						success++
					}
					if c1.IsClosed() || c2.IsClosed() {
						if (err1 == ErrConnClosed && err3 == ErrConnClosed) || (err2 == ErrConnClosed && err4 == ErrConnClosed) {
							closedAtEntry++
						} else {
							closed++
						}
						c1.Close()
						c2.Close()
						// Need to reconnect.
						var err error
						c2, err = lt2.Dial(context.Background(), addr.String(), privkey1.PubKey().SerializeCompressed())
						if err != nil {
							t.Error(err)
						}
						c1 = <-ch
					} else if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
						// Likely "context canceled" error on one or both.
						recoverable++
					}
				}
				close(quit)

				t.Logf(`
	success: %v
	closed: %v
	closedAtEntry: %v
	recoverable: %v`,
					success, closed, closedAtEntry, recoverable)

				if !tc.doClose && closedAtEntry > 0 {
					// Context cancel not supposed to close Conn directly.
					t.Errorf("closedAtEntry > 0: %v", closedAtEntry)
				}
				if tc.doClose && recoverable > 0 {
					// IsClosed should have been true.
					t.Errorf("recoverable > 0: %v", recoverable)
				}

				if tc.iterations >= 200 {
					if !tc.doClose {
						if success == 0 || closed == 0 || recoverable == 0 {
							t.Error(success, closed, recoverable)
						}
					} else {
						if success == 0 || closed == 0 || closedAtEntry == 0 {
							t.Error(success, closed, recoverable)
						}
					}
				}
			})
		}
	})
}

func fileDescriptorCount(t *testing.T) int {
	c := exec.Command("lsof", "-p", strconv.Itoa(os.Getpid()))
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	c.Stdout = outBuf
	c.Stderr = errBuf
	err := c.Run()
	if err != nil {
		t.Error(errBuf.String())
		return 0
	}
	// There might be some extra lines, this is not an exact count of file descriptors,
	// but good enough for comparison.
	return bytes.Count(outBuf.Bytes(), []byte("\n"))
}
