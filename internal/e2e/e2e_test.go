package e2e

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestE2ERoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	errCh := make(chan error, 1)
	go func() {
		srv, err := HandshakeAsServer(c2)
		if err != nil {
			errCh <- err
			return
		}
		buf := make([]byte, 64)
		n, err := srv.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		_, err = srv.Write([]byte("pong:" + string(buf[:n])))
		errCh <- err
	}()

	cli, err := HandshakeAsClient(c1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Write([]byte("hello-e2e")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := cli.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], []byte("pong:hello-e2e")) {
		t.Fatalf("got %q", buf[:n])
	}
}
