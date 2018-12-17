/*
Copyright 2016, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package network

import (
	"github.com/cossacklabs/themis/gothemis/errors"
	"net"
	"time"
)

const (
	// DefaultNetworkTimeout default timeout for network related communication
	DefaultNetworkTimeout = time.Second * 60
)

// ErrUnsupportedListener represents net.Listener type unknown to Acra.
var ErrUnsupportedListener = errors.New("unsupported network Listener type")

// DeadlineListener is extended net.Listener interface with SetDeadline method that added for abstraction of calling
// SetDeadline between two listener types (TcpListener and UnixListener) that support this method
type DeadlineListener interface {
	net.Listener
	SetDeadline(t time.Time) error
}

// CastListenerToDeadline casts any net.Listener to DeadlineListener
// or throws ErrUnsupportedListener error.
func CastListenerToDeadline(listener net.Listener) (DeadlineListener, error) {
	listener = UnwrapSafeCloseListener(listener)
	deadlineListener, ok := listener.(DeadlineListener)
	if ok {
		return deadlineListener, nil
	}
	return nil, ErrUnsupportedListener
}
