package tunnel

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

// UpgradeAgentWS upgrades an HTTP request to a yamux-capable agent session.
func UpgradeAgentWS(w http.ResponseWriter, r *http.Request) (*Session, error) {
	wc, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // agents may dial without Origin
	})
	if err != nil {
		return nil, err
	}
	conn := websocket.NetConn(r.Context(), wc, websocket.MessageBinary)
	sess, err := ServerSession(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	sess.transport = "websocket"
	return sess, nil
}

// ClientWSSession dials a WebSocket agent endpoint and opens a yamux client session.
func ClientWSSession(ctx context.Context, wsURL string, header http.Header) (*Session, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	wc, _, err := websocket.Dial(dialCtx, wsURL, &websocket.DialOptions{
		HTTPHeader: header,
	})
	if err != nil {
		return nil, fmt.Errorf("ws dial: %w", err)
	}
	conn := websocket.NetConn(ctx, wc, websocket.MessageBinary)
	sess, err := ClientSession(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	sess.transport = "websocket"
	return sess, nil
}
