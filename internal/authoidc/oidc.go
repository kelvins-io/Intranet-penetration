package authoidc

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/kelvins-io/Intranet-penetration/internal/config"
	"golang.org/x/oauth2"
)

type Provider struct {
	cfg      config.OIDCConfig
	provider *oidc.Provider
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	mu       sync.Mutex
	states   map[string]time.Time
}

func New(cfg config.OIDCConfig) (*Provider, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, fmt.Errorf("oidc issuer/client_id/redirect_url required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	oauth := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	return &Provider{
		cfg:      cfg,
		provider: p,
		oauth:    oauth,
		verifier: p.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		states:   make(map[string]time.Time),
	}, nil
}

func (p *Provider) Enabled() bool { return p != nil }

func (p *Provider) AuthCodeURL(state string) string {
	p.mu.Lock()
	p.states[state] = time.Now().Add(10 * time.Minute)
	p.mu.Unlock()
	return p.oauth.AuthCodeURL(state)
}

func (p *Provider) ValidateState(state string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	exp, ok := p.states[state]
	if !ok {
		return false
	}
	delete(p.states, state)
	return time.Now().Before(exp)
}

type Claims struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	Sub   string `json:"sub"`
}

func (p *Provider) Exchange(ctx context.Context, code string) (*Claims, error) {
	tok, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, fmt.Errorf("no id_token in token response")
	}
	idTok, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	var claims Claims
	if err := idTok.Claims(&claims); err != nil {
		return nil, err
	}
	if claims.Email == "" {
		return nil, fmt.Errorf("email claim missing")
	}
	if len(p.cfg.AllowedDomains) > 0 {
		ok := false
		email := strings.ToLower(claims.Email)
		for _, d := range p.cfg.AllowedDomains {
			if strings.HasSuffix(email, "@"+strings.ToLower(d)) {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("email domain not allowed")
		}
	}
	return &claims, nil
}

// DevHandler is unused placeholder for future mock IdP.
func DevHandler() http.Handler { return http.NotFoundHandler() }
