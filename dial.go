package lntransport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Dial attempts to make an outgoing connection.
//
// Cancelling the context aborts the connection attempt, but has no effect on a successfully returned connection.
//
// See func net.Dialer.DialContext for a description of the address parameter. The network is "tcp".
//
// remotePubkey is the pubkey that the remote party uses for transport encryption.
// About the format of remotePubkey, see pkg.go.dev/github.com/decred/dcrd/dcrec/secp256k1/v4#ParsePubKey
func (lt *LnTransport) Dial(ctx context.Context, address string, remotePubkey []byte, options ...func(*net.Dialer)) (*Conn, error) {
	// Catch illegal calls.
	if lt.privkey == nil {
		return nil, errors.New("LnTransport not properly created, must be gotten from New")
	}
	if lt.isClosed() {
		return nil, ErrLnTransportClosed
	}

	// Parse the remotePubkey.
	remotePub, err := secp256k1.ParsePubKey(remotePubkey)
	if err != nil {
		return nil, fmt.Errorf("remotePubkey parse error: %w", err)
	}

	dialer := &net.Dialer{}
	for _, option := range options {
		option(dialer)
	}
	netConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}

	conn := newConn()
	conn.parentClosed = lt.closed
	conn.contexts = lt.contexts
	conn.conn = netConn.(*net.TCPConn)
	conn.noise = newMachine(true, lt.privkey, remotePub)
	rollback := true
	defer func() {
		if rollback {
			conn.Close()
		}
	}()

	// Let contextWatcher interrupt the reads/writes if the context cancels.
	cinfo := contextInfo{
		ctx: ctx,
		contextInfoComparable: contextInfoComparable{
			conn:    conn.conn,
			isRead:  true,
			isWrite: true,
		},
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	select {
	case lt.contexts <- cinfo:
	case <-lt.closed:
		return nil, ErrLnTransportClosed
	}

	// Reset the conn deadline.
	// Can't count on the contextWatcher to have time to do that before this thread reaches the write.
	conn.conn.SetDeadline(time.Time{})
	// If the context has already expired, and the contextWatcher handled the expiry before we reset the deadline om the line above,
	// then the expiry action (setting instant deadline) would be ineffectual in contextWatcher,
	// so we need to handle expiry at this point to be safe.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Code snippet copied and modified from github.com/lightningnetwork/lnd/brontide/conn.go
	// with same licence (MIT) as this project and the following copyright notice:
	// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers

	// Initiate the handshake by sending the first act to the receiver.
	actOne, err := conn.noise.GenActOne()
	if err != nil {
		return nil, err
	}
	if _, err := conn.conn.Write(actOne[:]); err != nil {
		return nil, maybeClosedExpiredErr(lt.closed, ctx.Err(), err)
	}
	// We'll ensure that we get ActTwo from the remote peer in a timely
	// manner. If they don't respond within handshakeReadTimeout, then
	// we'll kill the connection.
	err = conn.conn.SetReadDeadline(time.Now().Add(handshakeReadTimeout))
	if err != nil {
		return nil, err
	}
	// If the first act was successful (we know that address is actually
	// remotePub), then read the second act after which we'll be able to
	// send our static public key to the remote peer with strong forward
	// secrecy.
	var actTwo [actTwoSize]byte
	if _, err := io.ReadFull(conn.conn, actTwo[:]); err != nil {
		return nil, maybeClosedExpiredErr(lt.closed, ctx.Err(), err)
	}
	if err := conn.noise.RecvActTwo(actTwo); err != nil {
		return nil, err
	}
	// Finally, complete the handshake by sending over our encrypted static
	// key and execute the final ECDH operation.
	actThree, err := conn.noise.GenActThree()
	if err != nil {
		return nil, err
	}
	if _, err := conn.conn.Write(actThree[:]); err != nil {
		return nil, maybeClosedExpiredErr(lt.closed, ctx.Err(), err)
	}

	// Stop monitoring the context to cancel reads/writes.
	cinfo.remove = true
	select {
	case lt.contexts <- cinfo:
	case <-lt.closed:
		return nil, ErrLnTransportClosed
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	rollback = false
	return conn, nil
}

func maybeClosedExpiredErr(closed <-chan struct{}, ctxErr, err error) error {
	select {
	case <-closed:
		// LnTransport closed, which caused the context to be treated as cancelled, interrupting the read/write.
		return ErrLnTransportClosed
	default:
	}
	if ctxErr != nil {
		// Context expired, which will provoke a Deadline exceeded error, but don't show that to the caller.
		return ctxErr
	}
	return err
}
