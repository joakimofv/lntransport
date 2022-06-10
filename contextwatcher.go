package lntransport

import (
	"context"
	"net"
	"reflect"
	"time"
)

type contextInfo struct {
	ctx    context.Context
	remove bool // either is is an add or a remove.
	contextInfoComparable
}

// Comparable struct for matching the remove with an earlier add.
type contextInfoComparable struct {
	conn    net.Conn // Only use with SetDeadline, SetReadDeadline, SetWriteDeadline
	isRead  bool
	isWrite bool
}

func (lt *LnTransport) contextWatcher() {
	defer lt.wg.Done()

	lt.cases = make([]reflect.SelectCase, 2)
	// Signal to quit.
	lt.cases[0] = reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(lt.closed),
	}
	// Add/remove context to monitor.
	lt.cases[1] = reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(lt.contexts),
	}
	// List of conns in the same order as their context channels appear in ´lt.cases´ (shifted by 2).
	var comparables []contextInfoComparable

	// Select loop.
	for {
		i, v, _ := reflect.Select(lt.cases)
		switch i {
		case 0:
			// Quit.
			// Treat all contexts as expired, because we can't monitor them anymore and ignoring them might lead to Send/Receive waiting forever.
			for _, comparable := range comparables {
				comparable.conn.SetDeadline(time.Now())
			}
			// Done. We won't receive contexts anymore, senders must select on <-lt.closed to not get stuck.
			return
		case 1:
			// Add/remove.
			cinfo := v.Interface().(contextInfo)
			// First clean any old context that refers to the same contextInfoComparable.
			// Either it is a remove order,
			// or it is a new Send/Receive and the the old context may not have expired,
			// and we don't send a remove signal after Send/Receive because cleaning here is more efficient
			// (one less triggering of the Select).
			for k, comparable := range comparables {
				if comparable == cinfo.contextInfoComparable {
					comparables = append(comparables[:k], comparables[k+1:]...)
					lt.cases = append(lt.cases[:k+2], lt.cases[k+2+1:]...)
					break
				}
			}
			// Reset the conn deadline.
			switch {
			case cinfo.isRead && cinfo.isWrite:
				cinfo.conn.SetDeadline(time.Time{})
			case cinfo.isRead:
				cinfo.conn.SetReadDeadline(time.Time{})
			case cinfo.isWrite:
				cinfo.conn.SetWriteDeadline(time.Time{})
				//default:
				//	panic("not supposed to happen")
			}
			if !cinfo.remove {
				// Add the new context and contextInfoComparable.
				comparables = append(comparables, cinfo.contextInfoComparable)
				lt.cases = append(lt.cases, reflect.SelectCase{
					Dir:  reflect.SelectRecv,
					Chan: reflect.ValueOf(cinfo.ctx.Done()),
				})
			}
		default:
			// A context expired.
			comparable := comparables[i-2]
			// Set the conn deadline to instant, it will interrupt.
			switch {
			case comparable.isRead && comparable.isWrite:
				comparable.conn.SetDeadline(time.Now())
			case comparable.isRead:
				comparable.conn.SetReadDeadline(time.Now())
			case comparable.isWrite:
				comparable.conn.SetWriteDeadline(time.Now())
				//default:
				//	panic("not supposed to happen")
			}
			// Remove the current select case.
			comparables = append(comparables[:i-2], comparables[i-2+1:]...)
			lt.cases = append(lt.cases[:i], lt.cases[i+1:]...)
		}
	}
}
