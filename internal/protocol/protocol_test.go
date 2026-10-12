package protocol

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte(`{"type":"ping"}`)
	if err := WriteFrame(&buf, payload); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q want %q", got, payload)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	hello := Hello{Version: Version, Token: "t", AgentID: "a"}
	if err := WriteJSON(&buf, MsgHello, hello); err != nil {
		t.Fatal(err)
	}
	env, err := ReadJSON(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if env.Type != MsgHello {
		t.Fatalf("type %s", env.Type)
	}
	var decoded Hello
	if err := DecodeBody(env, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Token != "t" || decoded.AgentID != "a" {
		t.Fatalf("decoded %+v", decoded)
	}
}
