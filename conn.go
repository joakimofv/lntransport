package lntransport

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Conn is a network connection with transport encrypted according to the protocol.
//
// Must be created through LnTransport.Dial or LnTransport.Listen.
// Close should be called to ensure resources are released.
//
// Conn is safe for concurrent use by multiple goroutines.
// Sends and Receives are serialized so that only one of each will write/read on the network connection at a time.
type Conn struct {
	sendSemaphore    chan struct{}
	receiveSemaphore chan struct{}
	closed           chan struct{}
	closedMutex      *sync.RWMutex

	// readBuf is a buffer for receiving, decrypting and storing the message.
	// Hopefully its storage will be reused between all steps and different reads, reducing allocations, but that is up to the compiler.
	readBuf   *bytes.Buffer
	encHeader [encHeaderSize]byte

	parentClosed <-chan struct{}
	contexts     chan<- contextInfo
	conn         *net.TCPConn
	noise        *machine
}

func newConn() *Conn {
	c := &Conn{
		sendSemaphore:    make(chan struct{}, 1),
		receiveSemaphore: make(chan struct{}, 1),
		closed:           make(chan struct{}),
		closedMutex:      new(sync.RWMutex),
		readBuf:          new(bytes.Buffer),
	}
	c.sendSemaphore <- struct{}{}
	c.receiveSemaphore <- struct{}{}
	return c
}

// Close closes the underlying network connection. Idempotent.
//
// Any ongoing, or future, Send or Receive calls will be unblocked and return a non-nil error.
func (c *Conn) Close() error {
	_, err := c.close(false, false)
	return err
}

// close does the close in a cuncurrency safe way.
// On return the closed-channel is closed and all semaphores held.
func (c *Conn) close(sendSemaphoreHeld, receiveSemaphoreHeld bool) (bool, error) {
	c.closedMutex.Lock()
	select {
	case <-c.closed:
		c.closedMutex.Unlock()
		return false, nil
	default:
	}
	close(c.closed)
	c.closedMutex.Unlock()
	err := c.conn.Close()

	// After closing the conn, do some cleanup.
	// This way ongoing send/receive won't block the sendSemaphore/receiveSemaphore.
	// Stop monitoring any context related to this conn.
	cinfo := contextInfo{
		remove: true,
		contextInfoComparable: contextInfoComparable{
			conn:    c.conn,
			isWrite: true,
		},
	}
	if !sendSemaphoreHeld {
		<-c.sendSemaphore
	}
	select {
	case c.contexts <- cinfo:
	case <-c.parentClosed:
	}
	cinfo.isWrite = false
	cinfo.isRead = true
	if !receiveSemaphoreHeld {
		<-c.receiveSemaphore
	}
	select {
	case c.contexts <- cinfo:
	case <-c.parentClosed:
	}

	return true, err
}

// IsClosed reports if the connection has been closed, either by a call to Close or due to becoming defunct after a failed Send/Receive.
func (c *Conn) IsClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// Send writes the next message to the connection.
// Blocks until the whole message is written, the Conn or LnTransport is closed, or the context expires.
//
// A non-nil error guarantees that the message was not fully sent.
// Then, in case there was a partial send, the connection may become defunct and is closed.
// Check for it with IsClosed, comparing the returned error to ErrConnClosed is not enough.
//
// You must then dial up a new connection and send the message on that, if you want to proceed with the send.
//
// If the connection was not closed then inspect the error to see if it is recoverable by doing another send on the same connection.
// Known unrecoverable errors: ErrMaxMessageLengthExceeded
func (c *Conn) Send(ctx context.Context, msg []byte) error {
	// Wait for the semaphore or one of the exit conditions.
	weClose := false
	select {
	case <-c.sendSemaphore:
		defer func() {
			if !weClose {
				c.sendSemaphore <- struct{}{}
			}
		}()
	case <-c.parentClosed:
		c.close(false, false)
		return ErrLnTransportClosed
	case <-c.closed:
		select {
		case <-c.parentClosed:
			// Takes precedence, explains more.
			return ErrLnTransportClosed
		default:
			return ErrConnClosed
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	if err := c.noise.encryptMessage(msg); err != nil {
		weClose, _ = c.close(true, false)
		return err
	}
	rollback := true
	defer func() {
		if rollback {
			c.noise.rollbackEncryptMessage()
		}
	}()

	// Let contextWatcher interrupt the operation if the context cancels.
	cinfo := contextInfo{
		ctx: ctx,
		contextInfoComparable: contextInfoComparable{
			conn:    c.conn,
			isWrite: true,
		},
	}
	select {
	case c.contexts <- cinfo:
	case <-c.parentClosed:
		return ErrLnTransportClosed
	case <-ctx.Done():
		return ctx.Err()
	}

	// Reset the conn deadline.
	// Can't count on the contextWatcher to have time to do that before this thread reaches the write.
	c.conn.SetWriteDeadline(time.Time{})
	// If the context has already expired, and the contextWatcher handled the expiry before we reset the deadline on the line above,
	// then the expiry action (setting instant deadline) would be ineffectual in contextWatcher,
	// so we need to handle expiry at this point to be safe.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	n, err := c.conn.Write(c.noise.encryptedMessage)
	if err != nil {
		//log.Printf("[%T] %[1]v, n=%v", err, n)
		if netError, ok := err.(net.Error); ok && !netError.Timeout() {
			// Assume that a non-timeout error is unrecoverable.
			weClose, _ = c.close(true, false)
		} else if n > 0 {
			// Partial write breaks the protocol, must become defunct.
			weClose, _ = c.close(true, false)
		}
		select {
		case <-c.parentClosed:
			// LnTransport closed, which caused the context to be treated as cancelled, interrupting the write.
			weClose, _ = c.close(true, false)
			return ErrLnTransportClosed
		case <-ctx.Done():
			// Context expired, which will provoke a Deadline exceeded error, but don't show that to the caller.
			return ctx.Err()
		default:
			return err
		}
	}
	rollback = false
	return nil
}

// Receive reads the next message on the connection and returns it
// as a slice of bytes. Blocks until a message arrives, the Conn or LnTransport is closed, or the context expires.
//
// The returned byte slice is not safe for use after Receive is called again,
// the underlying storage will be reused on the next read.
//
// A non-nil error means that a message was not fully received (and a partial message won't be returned).
// Then the connection might have been closed.
// Check for it with IsClosed, comparing the returned error to ErrConnClosed is not enough.
func (c *Conn) Receive(ctx context.Context) ([]byte, error) {
	// Wait for the semaphore or one of the exit conditions.
	weClose := false
	select {
	case <-c.receiveSemaphore:
		defer func() {
			if !weClose {
				c.receiveSemaphore <- struct{}{}
			}
		}()
	case <-c.parentClosed:
		c.close(false, false)
		return nil, ErrLnTransportClosed
	case <-c.closed:
		select {
		case <-c.parentClosed:
			// Takes precedence, explains more.
			return nil, ErrLnTransportClosed
		default:
			return nil, ErrConnClosed
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Let contextWatcher interrupt the operation if the context cancels.
	cinfo := contextInfo{
		ctx: ctx,
		contextInfoComparable: contextInfoComparable{
			conn:   c.conn,
			isRead: true,
		},
	}
	select {
	case c.contexts <- cinfo:
	case <-c.parentClosed:
		return nil, ErrLnTransportClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Reset the conn deadline.
	// Can't count on the contextWatcher to have time to do that before this thread reaches the read.
	c.conn.SetReadDeadline(time.Time{})
	// If the context has already expired, and the contextWatcher handled the expiry before we reset the deadline on the line above,
	// then the expiry action (setting instant deadline) would be ineffectual in contextWatcher,
	// so we need to handle expiry at this point to be safe.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Read the header.
	n, err := io.ReadFull(c.conn, c.encHeader[:])
	if err != nil {
		if netError, ok := err.(net.Error); ok && !netError.Timeout() {
			// Assume that a non-timeout error is unrecoverable.
			weClose, _ = c.close(false, true)
		} else if n > 0 {
			// Partial write breaks the protocol, must become defunct.
			weClose, _ = c.close(false, true)
		}
		select {
		case <-c.parentClosed:
			// LnTransport closed, which caused the context to be treated as cancelled, interrupting the read.
			weClose, _ = c.close(false, true)
			return nil, ErrLnTransportClosed
		case <-ctx.Done():
			// Context expired, which will provoke a Deadline exceeded error, but don't show that to the caller.
			return nil, ctx.Err()
		default:
			return nil, err
		}
	}
	// Decrypt the header.
	pktLen, err := c.noise.decryptHeader(c.encHeader[:])
	if err != nil {
		weClose, _ = c.close(false, true)
		return nil, err
	}

	// Read the body.
	c.readBuf.Reset()
	_, err = io.CopyN(c.readBuf, c.conn, int64(pktLen))
	if err != nil {
		// The header has been read, then not fully reading the body will break the protocol,
		// so the conn must be closed.
		weClose, _ = c.close(false, true)
		select {
		case <-c.parentClosed:
			return nil, ErrLnTransportClosed
		case <-ctx.Done():
			// Context expired, which will provoke a Deadline exceeded error, but don't show that to the caller.
			return nil, ctx.Err()
		default:
			return nil, err
		}
	}
	// Decrypt the body.
	b := c.readBuf.Bytes()
	msg, err := c.noise.decryptBody(b)
	if err != nil {
		weClose, _ = c.close(false, true)
		return nil, err
	}
	return msg, nil
}

// LocalAddrPort returns the local network address.
func (c *Conn) LocalAddrPort() netip.AddrPort {
	return c.conn.LocalAddr().(*net.TCPAddr).AddrPort()
}

// RemoteAddrPort returns the remote network address.
func (c *Conn) RemoteAddrPort() netip.AddrPort {
	return c.conn.RemoteAddr().(*net.TCPAddr).AddrPort()
}

// RemotePubkey returns the remote peer's static public key.
func (c *Conn) RemotePubkey() [33]byte {
	var b [33]byte
	copy(b[:], c.noise.remoteStatic.SerializeCompressed())
	return b
}

// LocalPubkey returns the own static public key.
func (c *Conn) LocalPubkey() [33]byte {
	var b [33]byte
	copy(b[:], c.noise.localStatic.PubKey().SerializeCompressed())
	return b
}