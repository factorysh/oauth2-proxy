package providers

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
)

var (
	// extra headers required by the DigitalOcean API when making authenticated requests
	digitalOceanAuthorizationHeaders = map[string]string{
		acceptHeader: acceptApplicationJSON,
	}
)

// DigitalOceanProvider represents a DigitalOcean based Identity Provider
type DigitalOceanProvider struct {
	*ProviderData
}

var _ Provider = (*DigitalOceanProvider)(nil)

// NewDigitalOceanProvider initiates a new DigitalOceanProvider
func NewDigitalOceanProvider(p *ProviderData) *DigitalOceanProvider {
	p.ProviderName = "DigitalOcean"
	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{Scheme: "https",
			Host: "cloud.digitalocean.com",
			Path: "/v1/oauth/authorize",
		}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{Scheme: "https",
			Host: "cloud.digitalocean.com",
			Path: "/v1/oauth/token",
		}
	}
	if p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{Scheme: "https",
			Host: "api.digitalocean.com",
			Path: "/v2/account",
		}
	}
	if p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}
	if p.Scope == "" {
		p.Scope = "read"
	}
	return &DigitalOceanProvider{ProviderData: p}
}

// GetEmailAddress returns the Account email address
func (p *DigitalOceanProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = getAuthorizationHeader(tokenTypeBearer, s.AccessToken, digitalOceanAuthorizationHeaders)

	json, err := requests.Request(req)
	if err != nil {
		return "", err
	}

	email, err := json.GetPath("account", "email").String()
	if err != nil {
		return "", err
	}
	return email, nil
}

// ValidateSessionState validates the AccessToken
func (p *DigitalOceanProvider) ValidateSessionState(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, getAuthorizationHeader(tokenTypeBearer, s.AccessToken, digitalOceanAuthorizationHeaders))
}
