package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrConflict      = errors.New("conflict")
	ErrUnauthorized  = errors.New("unauthorized")
	ErrQuotaExceeded = errors.New("quota exceeded")
)

type Store struct {
	mu   sync.RWMutex
	path string
	data Snapshot
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, data: Snapshot{}}
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
			if err := json.Unmarshal(b, &s.data); err != nil {
				return nil, fmt.Errorf("load store: %w", err)
			}
		}
	}
	return s, nil
}

func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func NewID(prefix string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return prefix + "_" + hex.EncodeToString(b[:])
}

func NewToken(nbytes int) string {
	b := make([]byte, nbytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// Bootstrap ensures a default tenant, admin user and agent token exist.
func (s *Store) Bootstrap(adminEmail, adminPassword, adminAPIKey, agentToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.data.Tenants) == 0 {
		now := time.Now().UTC()
		tenant := Tenant{
			ID:        NewID("ten"),
			Name:      "Default",
			Slug:      "default",
			Quota:     DefaultQuota(),
			CreatedAt: now,
		}
		s.data.Tenants = append(s.data.Tenants, tenant)

		if adminAPIKey == "" {
			adminAPIKey = NewToken(24)
		}
		hash, err := HashPassword(adminPassword)
		if err != nil {
			return err
		}
		if adminEmail == "" {
			adminEmail = "admin@localhost"
		}
		s.data.Users = append(s.data.Users, User{
			ID:           NewID("usr"),
			TenantID:     tenant.ID,
			Email:        adminEmail,
			DisplayName:  "Admin",
			Role:         RoleAdmin,
			PasswordHash: hash,
			APIKey:       adminAPIKey,
			CreatedAt:    now,
		})

		if agentToken == "" {
			agentToken = NewToken(16)
		}
		s.data.AgentTokens = append(s.data.AgentTokens, AgentToken{
			ID:        NewID("atk"),
			TenantID:  tenant.ID,
			Name:      "default",
			Token:     agentToken,
			CreatedAt: now,
		})
		return s.persistLocked()
	}

	// Ensure configured agent token exists for first tenant (backward compatible).
	if agentToken != "" {
		for _, t := range s.data.AgentTokens {
			if t.Token == agentToken && !t.Revoked {
				return nil
			}
		}
		s.data.AgentTokens = append(s.data.AgentTokens, AgentToken{
			ID:        NewID("atk"),
			TenantID:  s.data.Tenants[0].ID,
			Name:      "bootstrap",
			Token:     agentToken,
			CreatedAt: time.Now().UTC(),
		})
		return s.persistLocked()
	}
	return nil
}

func (s *Store) Audit(tenantID, actor, action, target, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Audits = append(s.data.Audits, AuditEvent{
		ID:        NewID("aud"),
		TenantID:  tenantID,
		Actor:     actor,
		Action:    action,
		Target:    target,
		Detail:    detail,
		CreatedAt: time.Now().UTC(),
	})
	// Keep last 2000 events.
	if len(s.data.Audits) > 2000 {
		s.data.Audits = s.data.Audits[len(s.data.Audits)-2000:]
	}
	_ = s.persistLocked()
}

func (s *Store) ListAudits(tenantID string, limit int) []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	out := make([]AuditEvent, 0, limit)
	for i := len(s.data.Audits) - 1; i >= 0 && len(out) < limit; i-- {
		a := s.data.Audits[i]
		if tenantID != "" && a.TenantID != tenantID {
			continue
		}
		out = append(out, a)
	}
	return out
}

func (s *Store) ResolveAgentToken(token string) (*AgentToken, *Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.data.AgentTokens {
		at := &s.data.AgentTokens[i]
		if at.Token == token && !at.Revoked {
			ten, err := s.tenantByIDLocked(at.TenantID)
			if err != nil {
				return nil, nil, err
			}
			cp := *at
			return &cp, ten, nil
		}
	}
	return nil, nil, ErrUnauthorized
}

func (s *Store) ResolveUserAPIKey(key string) (*User, *Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.data.Users {
		u := &s.data.Users[i]
		if u.APIKey == key {
			ten, err := s.tenantByIDLocked(u.TenantID)
			if err != nil {
				return nil, nil, err
			}
			cp := *u
			cp.PasswordHash = ""
			return &cp, ten, nil
		}
	}
	return nil, nil, ErrUnauthorized
}

func (s *Store) AuthenticatePassword(email, password string) (*User, *Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	email = strings.ToLower(strings.TrimSpace(email))
	for i := range s.data.Users {
		u := &s.data.Users[i]
		if strings.ToLower(u.Email) == email {
			if !CheckPassword(u.PasswordHash, password) {
				return nil, nil, ErrUnauthorized
			}
			ten, err := s.tenantByIDLocked(u.TenantID)
			if err != nil {
				return nil, nil, err
			}
			cp := *u
			cp.PasswordHash = ""
			return &cp, ten, nil
		}
	}
	return nil, nil, ErrUnauthorized
}

func (s *Store) tenantByIDLocked(id string) (*Tenant, error) {
	for i := range s.data.Tenants {
		if s.data.Tenants[i].ID == id {
			cp := s.data.Tenants[i]
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) GetTenant(id string) (*Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tenantByIDLocked(id)
}

func (s *Store) GetTenantBySlug(slug string) (*Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	slug = strings.ToLower(slug)
	for i := range s.data.Tenants {
		if s.data.Tenants[i].Slug == slug {
			cp := s.data.Tenants[i]
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) ListTenants() []Tenant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Tenant, len(s.data.Tenants))
	copy(out, s.data.Tenants)
	return out
}

func (s *Store) CreateTenant(name, slug string, quota Quota) (*Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	slug = strings.ToLower(strings.TrimSpace(slug))
	if slug == "" {
		return nil, fmt.Errorf("slug required")
	}
	for _, t := range s.data.Tenants {
		if t.Slug == slug {
			return nil, ErrConflict
		}
	}
	if quota.MaxAgents == 0 {
		quota = DefaultQuota()
	}
	ten := Tenant{
		ID:        NewID("ten"),
		Name:      name,
		Slug:      slug,
		Quota:     quota,
		CreatedAt: time.Now().UTC(),
	}
	s.data.Tenants = append(s.data.Tenants, ten)
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return &ten, nil
}

func (s *Store) UpdateTenantQuota(id string, quota Quota) (*Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Tenants {
		if s.data.Tenants[i].ID == id {
			s.data.Tenants[i].Quota = quota
			if err := s.persistLocked(); err != nil {
				return nil, err
			}
			cp := s.data.Tenants[i]
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) ListUsers(tenantID string) []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []User{}
	for _, u := range s.data.Users {
		if tenantID == "" || u.TenantID == tenantID {
			cp := u
			cp.PasswordHash = ""
			out = append(out, cp)
		}
	}
	return out
}

func (s *Store) CreateAgentToken(tenantID, name string) (*AgentToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.tenantByIDLocked(tenantID); err != nil {
		return nil, err
	}
	at := AgentToken{
		ID:        NewID("atk"),
		TenantID:  tenantID,
		Name:      name,
		Token:     NewToken(16),
		CreatedAt: time.Now().UTC(),
	}
	s.data.AgentTokens = append(s.data.AgentTokens, at)
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return &at, nil
}

func (s *Store) ListAgentTokens(tenantID string) []AgentToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []AgentToken{}
	for _, t := range s.data.AgentTokens {
		if tenantID == "" || t.TenantID == tenantID {
			out = append(out, t)
		}
	}
	return out
}

func (s *Store) RevokeAgentToken(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.AgentTokens {
		if s.data.AgentTokens[i].ID == id {
			s.data.AgentTokens[i].Revoked = true
			return s.persistLocked()
		}
	}
	return ErrNotFound
}

func (s *Store) CountOnlineAgents(tenantID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]struct{}{}
	for _, t := range s.data.Tunnels {
		if t.TenantID == tenantID && t.Online && t.AgentID != "" {
			seen[t.AgentID] = struct{}{}
		}
	}
	return len(seen)
}

func (s *Store) CountTunnels(tenantID string) (total, tcp int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.data.Tunnels {
		if t.TenantID != tenantID {
			continue
		}
		total++
		if t.Type == "tcp" {
			tcp++
		}
	}
	return
}

// CheckTunnelQuota validates connecting an agent with the given tunnel names/types.
// Existing tunnels for the same tenant+name are not double-counted (reconnect safe).
func (s *Store) CheckTunnelQuota(tenantID, agentID string, names []string, types []string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ten, err := s.tenantByIDLocked(tenantID)
	if err != nil {
		return err
	}
	existing := map[string]TunnelRecord{}
	agents := map[string]struct{}{}
	total, tcp := 0, 0
	for _, t := range s.data.Tunnels {
		if t.TenantID != tenantID {
			continue
		}
		existing[t.Name] = t
		total++
		if t.Type == "tcp" {
			tcp++
		}
		if t.Online && t.AgentID != "" {
			agents[t.AgentID] = struct{}{}
		}
	}
	addTunnels, addTCP := 0, 0
	for i, name := range names {
		if _, ok := existing[name]; ok {
			continue
		}
		addTunnels++
		if i < len(types) && types[i] == "tcp" {
			addTCP++
		}
	}
	if _, ok := agents[agentID]; !ok && agentID != "" {
		if len(agents)+1 > ten.Quota.MaxAgents {
			return fmt.Errorf("%w: agents", ErrQuotaExceeded)
		}
	}
	if total+addTunnels > ten.Quota.MaxTunnels {
		return fmt.Errorf("%w: tunnels", ErrQuotaExceeded)
	}
	if tcp+addTCP > ten.Quota.MaxTCP {
		return fmt.Errorf("%w: tcp ports", ErrQuotaExceeded)
	}
	return nil
}

func routeKey(tenantID, name string) string {
	return tenantID + "/" + name
}

func (s *Store) UpsertTunnel(rec TunnelRecord) (*TunnelRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for i := range s.data.Tunnels {
		t := &s.data.Tunnels[i]
		if t.TenantID == rec.TenantID && t.Name == rec.Name {
			t.Type = rec.Type
			t.LocalHint = rec.LocalHint
			if rec.Domain != "" {
				t.Domain = strings.ToLower(rec.Domain)
			}
			t.PublicAddr = rec.PublicAddr
			t.RemotePort = rec.RemotePort
			t.AgentID = rec.AgentID
			t.Online = rec.Online
			t.UpdatedAt = now
			if err := s.persistLocked(); err != nil {
				return nil, err
			}
			cp := *t
			return &cp, nil
		}
	}
	if rec.ID == "" {
		rec.ID = NewID("tun")
	}
	rec.Domain = strings.ToLower(rec.Domain)
	rec.CreatedAt = now
	rec.UpdatedAt = now
	s.data.Tunnels = append(s.data.Tunnels, rec)
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *Store) SetTunnelOnline(tenantID, name string, online bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Tunnels {
		t := &s.data.Tunnels[i]
		if t.TenantID == tenantID && t.Name == name {
			t.Online = online
			t.UpdatedAt = time.Now().UTC()
			_ = s.persistLocked()
			return
		}
	}
}

func (s *Store) MarkAgentOffline(tenantID, agentID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for i := range s.data.Tunnels {
		t := &s.data.Tunnels[i]
		if t.TenantID == tenantID && t.AgentID == agentID {
			t.Online = false
			t.UpdatedAt = time.Now().UTC()
			changed = true
		}
	}
	if changed {
		_ = s.persistLocked()
	}
}

func (s *Store) SetTunnelDomain(tenantID, name, domain string) (*TunnelRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain != "" {
		for _, t := range s.data.Tunnels {
			if t.Domain == domain && !(t.TenantID == tenantID && t.Name == name) {
				return nil, ErrConflict
			}
		}
	}
	for i := range s.data.Tunnels {
		t := &s.data.Tunnels[i]
		if t.TenantID == tenantID && t.Name == name {
			t.Domain = domain
			t.UpdatedAt = time.Now().UTC()
			if err := s.persistLocked(); err != nil {
				return nil, err
			}
			cp := *t
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) GetTunnel(tenantID, name string) (*TunnelRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.data.Tunnels {
		t := &s.data.Tunnels[i]
		if t.TenantID == tenantID && t.Name == name {
			cp := *t
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) FindTunnelByDomain(domain string) (*TunnelRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	domain = strings.ToLower(domain)
	for i := range s.data.Tunnels {
		t := &s.data.Tunnels[i]
		if t.Domain != "" && t.Domain == domain {
			cp := *t
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) ListTunnels(tenantID string) []TunnelRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []TunnelRecord{}
	for _, t := range s.data.Tunnels {
		if tenantID == "" || t.TenantID == tenantID {
			out = append(out, t)
		}
	}
	return out
}

func (s *Store) AdminAPIKey() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.data.Users {
		if u.Role == RoleAdmin {
			return u.APIKey
		}
	}
	return ""
}

func (s *Store) DefaultAgentToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.data.AgentTokens {
		if !t.Revoked {
			return t.Token
		}
	}
	return ""
}

// RouteKey exported for registry.
func RouteKey(tenantID, name string) string {
	return routeKey(tenantID, name)
}
