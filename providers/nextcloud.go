package providers

import (
	"context"
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
)

var (
	// extra headers required by the Nextcloud API when making authenticated requests
	nextcloudAuthorizationHeaders = map[string]string{
		acceptHeader: acceptApplicationJSON,
	}
)

// NextcloudProvider represents an Nextcloud based Identity Provider
type NextcloudProvider struct {
	*ProviderData
}

var _ Provider = (*NextcloudProvider)(nil)

// NewNextcloudProvider initiates a new NextcloudProvider
func NewNextcloudProvider(p *ProviderData) *NextcloudProvider {
	p.ProviderName = "Nextcloud"
	return &NextcloudProvider{ProviderData: p}
}

// GetEmailAddress returns the Account email address
func (p *NextcloudProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		p.ValidateURL.String(), nil)
	if err != nil {
		logger.Printf("failed building request %s", err)
		return "", err
	}
	req.Header = getAuthorizationHeader(tokenTypeBearer, s.AccessToken, nextcloudAuthorizationHeaders)
	json, err := requests.Request(req)
	if err != nil {
		logger.Printf("failed making request %s", err)
		return "", err
	}
	email, err := json.Get("ocs").Get("data").Get("email").String()
	return email, err
}
