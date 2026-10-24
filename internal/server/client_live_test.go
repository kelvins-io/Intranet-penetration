package server

import (
	"testing"
	"time"
)

func TestClientLiveRegistryKickMissing(t *testing.T) {
	r := newClientLiveRegistry()
	if err := r.Kick("nope", "x"); err == nil {
		t.Fatal("expected not found")
	}
	r.Register(&LiveClientSession{
		ID: "s1", TenantID: "t1", UserID: "u1", Email: "a@b.c",
		Connected: time.Now(),
	})
	list := r.List("t1")
	if len(list) != 1 || list[0].ID != "s1" {
		t.Fatalf("list=%v", list)
	}
	// Kick without underlying session still unregisters after WriteJSON fails path —
	// sess nil → ErrNotFound
	if err := r.Kick("s1", "bye"); err == nil {
		t.Fatal("expected not found without sess")
	}
}
