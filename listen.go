package lntransport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Listen handles incoming connection attempts.
// It returns a channel whereupon successful connections will be passed, and the local listening address.
// The channel will be closed when the listening is stopped.
//
// Cancelling the context stops the listening for new connections, but has no effect on successfully returned connections.
// Closing the LnTransport is another way to stop the listening.
//
// See func net.ListenConfig.Listen for a description of the address parameter. The network is "tcp".
func (lt *LnTransport) Listen(ctx context.Context, address string, options ...func(*net.ListenConfig)) (chan *Conn, netip.AddrPort, error) {
	// Catch illegal calls.
	if lt.privkey == nil {
		return nil, netip.AddrPort{}, errors.New("LnTransport not properly created, must be gotten from New")
	}
	lt.closedMutex.RLock()
	if lt.isClosed() {
		lt.closedMutex.RUnlock()
		return nil, netip.AddrPort{}, ErrLnTransportClosed
	}
	lt.wg.Add(2)
	lt.closedMutex.RUnlock()

	lcfg := &net.ListenConfig{}
	for _, option := range options {
		option(lcfg)
	}
	l, err := lcfg.Listen(ctx, "tcp", address)
	if err != nil {
		lt.wg.Done()
		return nil, netip.AddrPort{}, err
	}
	addrPort := l.Addr().(*net.TCPAddr).AddrPort()

	// The context needs to be cancelled if LnTransport is closed, and the listener be closed,
	// or else Accept can remain stuck while trying to exit.
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		defer lt.wg.Done()
		select {
		case <-ctx.Done():
		case <-lt.closed:
			cancel()
		}
		l.Close()
	}()

	// Spawn the listener goroutine.
	conns := make(chan *Conn)
	go func() {
		defer lt.wg.Done()

		// Code snippets copied and modified from github.com/lightningnetwork/lnd/brontide/listener.go
		// with same licence (MIT) as this project and the following copyright notice:
		// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers

		connsMutex := new(sync.RWMutex)
		handshakeSema := make(chan struct{}, lt.cfg.MaxParallelListenHandshakes)
		for i := 0; i < lt.cfg.MaxParallelListenHandshakes; i++ {
			handshakeSema <- struct{}{}
		}

		for {
			exit := false
			// First priority is to exit, second is to go on to Accept.
			select {
			case <-ctx.Done():
				exit = true
			default:
				select {
				case <-ctx.Done():
					exit = true
				case <-handshakeSema:
					// Go on to Accept.
				}
			}
			if exit {
				connsMutex.Lock()
				close(conns)
				connsMutex.Unlock()
				return
			}

			conn, err := l.Accept()
			if err != nil {
				// If it is context expired that closed the listener then it's not really an error, don't log it.
				if ctx.Err() != nil {
					// We will do some cleanup after the select and then exit.
					continue
				}
				if !lt.cfg.ListenErrNoLog {
					log.Printf("LnTransport.Listen Accept error: [%T] %[1]v\n", err)
				}
				if lt.cfg.ListenErrChan != nil {
					select {
					case lt.cfg.ListenErrChan <- ErrAndAddrPort{Err: err, AddrPort: addrPort}:
					case <-lt.closed:
					}
				}
				handshakeSema <- struct{}{}
				continue
			}

			lt.closedMutex.RLock()
			if lt.isClosed() {
				lt.closedMutex.RUnlock()
				conn.Close()
				continue
			}
			lt.wg.Add(1)
			lt.closedMutex.RUnlock()

			go lt.doHandshake(ctx, conn.(*net.TCPConn), conns, connsMutex, handshakeSema, addrPort)
		}
	}()

	return conns, addrPort, nil
}

// Function copied and modified from github.com/lightningnetwork/lnd/brontide/listener.go
// with same licence (MIT) as this project and the following copyright notice:
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
//
// doHandshake asynchronously performs the protocol handshake, so that it does
// not block the main accept loop. This prevents peers that delay writing to the
// connection from block other connection attempts.
func (lt *LnTransport) doHandshake(
	ctx context.Context,
	conn *net.TCPConn,
	conns chan<- *Conn,
	connsMutex *sync.RWMutex,
	handshakeSema chan<- struct{},
	addrPort netip.AddrPort,
) {
	defer lt.wg.Done()
	defer func() { handshakeSema <- struct{}{} }()

	select {
	case <-ctx.Done():
		conn.Close()
		return
	default:
	}

	remoteAddr := conn.RemoteAddr().(*net.TCPAddr).AddrPort()

	c := newConn()
	c.parentClosed = lt.closed
	c.contexts = lt.contexts
	c.conn = conn
	c.noise = newMachine(false, lt.privkey, nil)
	rollback := true
	defer func() {
		if rollback {
			c.Close()
		}
	}()

	// Let contextWatcher interrupt the reads/writes if the context cancels.
	cinfo := contextInfo{
		ctx: ctx,
		contextInfoComparable: contextInfoComparable{
			conn:    c.conn,
			isRead:  true,
			isWrite: true,
		},
	}
	select {
	case <-ctx.Done():
		return
	default:
	}
	select {
	case lt.contexts <- cinfo:
	case <-lt.closed:
		return
	}

	// Reset the conn deadline.
	// Can't count on the contextWatcher to have time to do that before this thread reaches the read.
	c.conn.SetDeadline(time.Time{})
	// If the context has already expired, and the contextWatcher handled the expiry before we reset the deadline om the line above,
	// then the expiry action (setting instant deadline) would be ineffectual in contextWatcher,
	// so we need to handle expiry at this point to be safe.
	select {
	case <-ctx.Done():
		return
	default:
	}

	// We'll ensure that we get ActOne from the remote peer in a timely
	// manner. If they don't respond within handshakeReadTimeout, then
	// we'll kill the connection.
	err := c.conn.SetReadDeadline(time.Now().Add(handshakeReadTimeout))
	if err != nil {
		if !lt.cfg.ListenErrNoLog {
			log.Println(err)
		}
		if lt.cfg.ListenErrChan != nil {
			select {
			case lt.cfg.ListenErrChan <- ErrAndAddrPort{Err: err, AddrPort: addrPort}:
			case <-lt.closed:
			}
		}
		return
	}
	// Attempt to carry out the first act of the handshake protocol. If the
	// connecting node doesn't know our long-term static public key, then
	// this portion will fail with a non-nil error.
	var actOne [actOneSize]byte
	if _, err := io.ReadFull(c.conn, actOne[:]); err != nil {
		err = maybeClosedExpiredErr(lt.closed, ctx.Err(), err)
		if !lt.cfg.ListenErrNoLog {
			log.Println(err)
		}
		if lt.cfg.ListenErrChan != nil {
			select {
			case lt.cfg.ListenErrChan <- ErrAndAddrPort{Err: err, AddrPort: addrPort}:
			case <-lt.closed:
			}
		}
		return
	}
	if err := c.noise.RecvActOne(actOne); err != nil {
		err = AuthError{err, remoteAddr}
		if !lt.cfg.ListenErrNoLog {
			log.Println(err)
		}
		if lt.cfg.ListenErrChan != nil {
			select {
			case lt.cfg.ListenErrChan <- ErrAndAddrPort{Err: err, AddrPort: addrPort}:
			case <-lt.closed:
			}
		}
		return
	}
	// Next, progress the handshake processes by sending over our ephemeral
	// key for the session along with an authenticating tag.
	actTwo, err := c.noise.GenActTwo()
	if err != nil {
		err = AuthError{err, remoteAddr}
		if !lt.cfg.ListenErrNoLog {
			log.Println(err)
		}
		if lt.cfg.ListenErrChan != nil {
			select {
			case lt.cfg.ListenErrChan <- ErrAndAddrPort{Err: err, AddrPort: addrPort}:
			case <-lt.closed:
			}
		}
		return
	}
	if _, err := c.conn.Write(actTwo[:]); err != nil {
		err = maybeClosedExpiredErr(lt.closed, ctx.Err(), err)
		if !lt.cfg.ListenErrNoLog {
			log.Println(err)
		}
		if lt.cfg.ListenErrChan != nil {
			select {
			case lt.cfg.ListenErrChan <- ErrAndAddrPort{Err: err, AddrPort: addrPort}:
			case <-lt.closed:
			}
		}
		return
	}
	select {
	case <-ctx.Done():
		return
	default:
	}
	// We'll ensure that we get ActTwo from the remote peer in a timely
	// manner. If they don't respond within handshakeReadTimeout, then
	// we'll kill the connection.
	err = c.conn.SetReadDeadline(time.Now().Add(handshakeReadTimeout))
	if err != nil {
		if !lt.cfg.ListenErrNoLog {
			log.Println(err)
		}
		if lt.cfg.ListenErrChan != nil {
			select {
			case lt.cfg.ListenErrChan <- ErrAndAddrPort{Err: err, AddrPort: addrPort}:
			case <-lt.closed:
			}
		}
		return
	}
	// Finally, finish the handshake processes by reading and decrypting
	// the connection peer's static public key. If this succeeds then both
	// sides have mutually authenticated each other.
	var actThree [actThreeSize]byte
	if _, err := io.ReadFull(c.conn, actThree[:]); err != nil {
		err = maybeClosedExpiredErr(lt.closed, ctx.Err(), err)
		if !lt.cfg.ListenErrNoLog {
			log.Println(err)
		}
		if lt.cfg.ListenErrChan != nil {
			select {
			case lt.cfg.ListenErrChan <- ErrAndAddrPort{Err: err, AddrPort: addrPort}:
			case <-lt.closed:
			}
		}
		return
	}
	if err := c.noise.RecvActThree(actThree); err != nil {
		err = AuthError{err, remoteAddr}
		if !lt.cfg.ListenErrNoLog {
			log.Println(err)
		}
		if lt.cfg.ListenErrChan != nil {
			select {
			case lt.cfg.ListenErrChan <- ErrAndAddrPort{Err: err, AddrPort: addrPort}:
			case <-lt.closed:
			}
		}
		return
	}

	// Stop monitoring the context to cancel reads/writes.
	cinfo.remove = true
	select {
	case lt.contexts <- cinfo:
	case <-lt.closed:
		return
	}

	connsMutex.RLock()
	select {
	case <-ctx.Done():
		connsMutex.RUnlock()
		return
	default:
	}
	rollback = false
	conns <- c
	connsMutex.RUnlock()
}

// AuthError may be passed on Config.ListenErrChan.
type AuthError struct {
	Err            error
	RemoteAddrPort netip.AddrPort
}

func (err AuthError) Error() string {
	return fmt.Sprintf("failed cryptographic authentication with %v: %v", err.RemoteAddrPort, err.Err)
}

func (err AuthError) Unwrap() error {
	return err.Err
}
