package lntransport

import (
	"context"
	"math"
	"math/rand"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

const NrOfNodes int = 5

func TestConcurrency(t *testing.T) {
	// Make sure we clean.
	fdsBefore := fileDescriptorCount(t)
	defer t.Run("fdcount", func(t *testing.T) {
		fdsAfter := fileDescriptorCount(t)
		if fdsBefore != fdsAfter {
			t.Errorf("file descriptors count expected %v, got %v", fdsBefore, fdsAfter)
		}
	})
	numGoroutineBefore := runtime.NumGoroutine()
	defer func() { // Can't be in a t.Run since that might start a goroutine.
		numGoroutineAfter := runtime.NumGoroutine()
		if numGoroutineBefore != numGoroutineAfter {
			t.Errorf("goroutine count expected %v, got %v", numGoroutineBefore, numGoroutineAfter)
		}
	}()

	rng := rand.New(rand.NewSource(1234))
	msg := make([]byte, math.MaxUint16)

	// Make a matrix of nodes that connect and send messages to eachother.
	var lts [NrOfNodes]*LnTransport
	var pubs [NrOfNodes][33]byte
	var addrs [NrOfNodes][2]netip.AddrPort
	connsMutex := new(sync.Mutex)
	var conns [NrOfNodes][NrOfNodes][]*Conn
	var sends [NrOfNodes][NrOfNodes]int32
	var receives [NrOfNodes][NrOfNodes]int32

	for i := 0; i < NrOfNodes; i++ {
		privkey, _ := btcec.NewPrivateKey()
		lt, _ := New(Config{Privkey: privkeyFixedSize(privkey.Serialize())})
		defer lt.Close()

		lts[i] = lt
		pubs[i] = lt.Pubkey()

		// Listen on two addresses.
		for n := 0; n < 2; n++ {
			ch, addr, err := lt.Listen(context.Background(), "localhost:0")
			if err != nil {
				t.Fatal(err)
			}
			addrs[i][n] = addr

			i := i
			go func() {
				for c := range ch {
					for j := 0; j < NrOfNodes; j++ {
						if pubs[j] == c.RemotePubkey() {
							connsMutex.Lock()
							conns[i][j] = append(conns[i][j], c)
							connsMutex.Unlock()
							// Set up receiving in two concurrent goroutines.
							for m := 0; m < 2; m++ {
								i := i
								j := j
								c := c
								go func() {
									for {
										_, err := c.Receive(context.Background())
										if err != nil {
											return
										}
										atomic.AddInt32(&receives[i][j], 1)
										//t.Logf("receives[%d][%d]", i, j)
									}
								}()
							}
							break
						}
					}
				}
			}()
		}
	}

	wgDials := new(sync.WaitGroup)
	for i := 0; i < NrOfNodes; i++ {
		lt := lts[i]
		// Dial some.
		for j := 0; j < NrOfNodes; j++ {
			for n := 0; n < rng.Intn(4); n++ {
				i := i
				j := j
				k := rng.Intn(2)
				wgDials.Add(1)
				go func() {
					defer wgDials.Done()
					c, err := lt.Dial(context.Background(), addrs[j][k].String(), pubs[j][:])
					if err != nil {
						t.Error(err)
						return
					}
					connsMutex.Lock()
					conns[i][j] = append(conns[i][j], c)
					connsMutex.Unlock()
					// Set up receiving in two concurrent goroutines.
					for m := 0; m < 2; m++ {
						i := i
						j := j
						c := c
						go func() {
							for {
								_, err := c.Receive(context.Background())
								if err != nil {
									return
								}
								atomic.AddInt32(&receives[i][j], 1)
								//t.Logf("receives[%d][%d]", i, j)
							}
						}()
					}
				}()
			}
		}
	}
	wgDials.Wait()

	// At this point all the dial-side conns are in the conns slice,
	// but not guaranteed all listen-side conns.
	// Waiting for the listening to complete is too complicated.
	// So we might send on some of the receive side conns and not on others,
	// which is fine since sending on each Conn is not necessary.

	wgSends := new(sync.WaitGroup)
	for i := 0; i < NrOfNodes; i++ {
		for j := 0; j < NrOfNodes; j++ {
			for _, c := range conns[i][j] {
				// Send some.
				for n := 0; n < rng.Intn(4); n++ {
					i := i
					j := j
					wgSends.Add(1)
					go func() {
						defer wgSends.Done()
						err := c.Send(context.Background(), msg)
						if err != nil {
							t.Error(err)
							return
						}
						atomic.AddInt32(&sends[i][j], 1)
					}()
				}
			}
		}
	}
	wgSends.Wait()

	table := "sends:"
	for i := 0; i < NrOfNodes; i++ {
		table += "\n"
		for j := 0; j < NrOfNodes; j++ {
			table += "[" + strconv.Itoa(int(sends[i][j])) + "]"
		}
	}
	//t.Log(table)

	// Now count the sends and receives and see that they correspond.
	timeout := time.After(time.Second)
	timedOut := false
	for {
		select {
		case <-timeout:
			timedOut = true
		default:
		}
		failed := false
		for i := 0; i < NrOfNodes; i++ {
			for j := 0; j < NrOfNodes; j++ {
				if sends[i][j] != receives[j][i] {
					failed = true
					if timedOut {
						t.Errorf("sends[%v][%v] %v != %v receives[%v][%v]", i, j, sends[i][j], receives[j][i], j, i)
					}
				}
			}
		}
		if !failed {
			break
		}
		if timedOut {
			t.Error("timeout")
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	for _, css := range conns {
		for _, cs := range css {
			for _, c := range cs {
				c.Close()
			}
		}
	}
}
