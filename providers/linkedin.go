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
	// extra headers required by the LinkedIn API when making authenticated requests
	linkedinAuthorizationHeaders = map[string]string{
		acceptHeader:  acceptApplicationJSON,
		"x-li-format": "json",
	}
)

// LinkedInProvider represents an LinkedIn based Identity Provider
type LinkedInProvider struct {
	*ProviderData
}

var _ Provider = (*LinkedInProvider)(nil)

// NewLinkedInProvider initiates a new LinkedInProvider
func NewLinkedInProvider(p *ProviderData) *LinkedInProvider {
	p.ProviderName = "LinkedIn"
	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{Scheme: "https",
			Host: "www.linkedin.com",
			Path: "/uas/oauth2/authorization"}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{Scheme: "https",
			Host: "www.linkedin.com",
			Path: "/uas/oauth2/accessToken"}
	}
	if p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{Scheme: "https",
			Host: "www.linkedin.com",
			Path: "/v1/people/~/email-address"}
	}
	if p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}
	if p.Scope == "" {
		p.Scope = "r_emailaddress r_basicprofile"
	}
	return &LinkedInProvider{ProviderData: p}
}

// GetEmailAddress returns the Account email address
func (p *LinkedInProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", p.ProfileURL.String()+"?format=json", nil)
	if err != nil {
		return "", err
	}
	req.Header = getAuthorizationHeader(tokenTypeBearer, s.AccessToken, linkedinAuthorizationHeaders)

	json, err := requests.Request(req)
	if err != nil {
		return "", err
	}

	email, err := json.String()
	if err != nil {
		return "", err
	}
	return email, nil
}

// ValidateSessionState validates the AccessToken
func (p *LinkedInProvider) ValidateSessionState(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, getAuthorizationHeader(tokenTypeBearer, s.AccessToken, linkedinAuthorizationHeaders))
}
