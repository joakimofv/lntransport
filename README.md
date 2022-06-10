[![Go Reference](https://pkg.go.dev/badge/github.com/joakimofv/lntransport.svg)](https://pkg.go.dev/github.com/joakimofv/lntransport)

lntransport
===========

An object that can dial and listen for Bitcoin Lightning Network (LN) connections.
The connection objects send/receive messages with a simple API that uses context.Context.

All is safe for concurrent use.

# Import

```go
	lntransport "github.com/joakimofv/lntransport"
```

# Usage

### [New](https://pkg.go.dev/github.com/joakimofv/lntransport#New)

```go
cfg := lntransport.Config{}
copy(cfg.Privkey[:], privkeyByteSlice)
lt, err := lntransport.New(cfg)
if err != nil {
	// Handle err.
}
defer lt.Close()
```

Privkey is a `[32]byte` array that needs to be a valid cryptographic key.
See [`Config`](https://pkg.go.dev/github.com/joakimofv/lntransport#Config).

### [Listen](https://pkg.go.dev/github.com/joakimofv/lntransport#LnTransport.Listen)

```go
ch, addr, err := lt.Listen(ctx, "127.0.0.1:12345")
```

Cancelling the `ctx` will abort the background listening process.

Incoming connections will be passed on the `ch` channel.
The channel will be closed when the listener is done so you can drain it like this:

```go
var c *Conn
for c = range ch {
	defer c.Close()
	// ...
}
```

### [Dial](https://pkg.go.dev/github.com/joakimofv/lntransport#LnTransport.Dial)

```go
c, err := lt.Dial(ctx, "1.2.3.4:12345", remotePubkey)
if err != nil {
	// Handle err.
}
defer c.Close()
```

The `remotePubkey` refers to the pubkey of the remote side, a byte slice, which you have to learn somehow before dialing.
For your own side you can get it with `lt.Pubkey()`.

### [Send](https://pkg.go.dev/github.com/joakimofv/lntransport#Conn.Send)

```go
err := c.Send(ctx, []byte("abcd..."))
if err != nil {
	if c.IsClosed() {
		// c has become defunct.
	}
	// Handle err.
}
```

### [Receive](https://pkg.go.dev/github.com/joakimofv/lntransport#Conn.Receive)

```go
msg, err := c.Receive(ctx)
if err != nil {
	if c.IsClosed() {
		// c has become defunct.
	}
	// Handle err.
}
```

# Error Handling

## Defunct Connection

Various network problems, counterparty problems, or bungled sends/receives may cause a connection object to become defunct.
Then it will close itself. Check if it has happened with [`c.IsClosed()`](https://pkg.go.dev/github.com/joakimofv/lntransport#Conn.IsClosed).

A closed connection can not be recovered. Be ready to dial again to make a new connection, or handle the situation in some other way.

## Failed Incoming Connection Attempts

Incoming connection attempts to a listener may fail. By default, when it happens a line will be printed with stdlib `log`.
Adjust what is done with these errors through fields in the [`Config`](https://pkg.go.dev/github.com/joakimofv/lntransport#Config).

## Limit On Number Of Connections

Having more than 30 000 connection object active from a single LnTransport can cause it to malfunction. Avoid that.
