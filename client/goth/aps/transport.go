package aps

import (
	"golang.org/x/oauth2"
	"net/http"
	"sync"
	"time"
)

const (
	defaultTokenType = "Bearer"
)

// Expired returns true if there is no access token or the
// access token is expired.
func Expired(t *oauth2.Token) bool {
	if t.AccessToken == "" {
		return true
	}
	if t.Expiry.IsZero() {
		return false
	}
	return t.Expiry.Before(time.Now())
}

// Transport represents an authorized transport.
// Provides currently in-use user token and allows to set a token to
// be used. If token expires, it tries to fetch a new token,
// if possible. Token fetching is thread-safe. If two or more
// concurrent requests are being made with the same expired token,
// one of the requests will wait for the other to refresh
// the existing token.
type Transport interface {
	// Authenticates the request with the existing token. If token is
	// expired, tries to refresh/fetch a new token.
	// Makes the request by delegating it to the default transport.
	RoundTrip(*http.Request) (*http.Response, error)
	// Returns the token authenticates the transport.
	// This operation is thread-safe.
	Token() *oauth2.Token
	// Sets a new token to authenticate the transport.
	// This operation is thread-safe.
	SetToken(token *oauth2.Token)
	// Refreshes the token if refresh is possible (such as in the
	// presense of a refresh token). Returns an error if refresh is
	// not possible. Refresh is thread-safe.
	RefreshToken() error
}
type authorizedTransport struct {
	fetcher TokenFetcher
	token   *oauth2.Token
	// Mutex to protect token during auto refreshments.
	mu sync.RWMutex
}

// NewAuthorizedTransport creates a tranport that uses the provided
// token fetcher to retrieve new tokens if there is no access token
// provided or it is expired.
func NewAuthorizedTransport(fetcher TokenFetcher, token *oauth2.Token) Transport {
	return &authorizedTransport{fetcher: fetcher, token: token}
}

// RoundTrip authorizes the request with the existing token.
// If token is expired, tries to refresh/fetch a new token.
func (t *authorizedTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	token := t.Token()
	if token == nil || Expired(token) {
		// Check if the token is refreshable.
		// If token is refreshable, don't return an error,
		// rather refresh.
		if err := t.RefreshToken(); err != nil {
			return nil, err
		}
		token = t.Token()
	}
	// To set the Authorization header, we must make a copy of the Request
	// so that we don't modify the Request we were given.
	// This is required by the specification of http.RoundTripper.
	req = cloneRequest(req)
	typ := token.TokenType
	if typ == "" {
		typ = defaultTokenType
	}
	req.Header.Set("Authorization", typ+" "+token.AccessToken)
	// Make the HTTP request.
	return DefaultTransport.RoundTrip(req)
}

// Token returns the existing token that authorizes the Transport.
func (t *authorizedTransport) Token() *oauth2.Token {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.token == nil {
		return nil
	}
	token := &oauth2.Token{
		AccessToken:  t.token.AccessToken,
		TokenType:    t.token.TokenType,
		RefreshToken: t.token.RefreshToken,
		Expiry:       t.token.Expiry,
	}
	return token
}

// SetToken sets a token to the transport in a thread-safe way.
func (t *authorizedTransport) SetToken(token *oauth2.Token) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.token = token
}

// RefreshToken retrieves a new token, if a refreshing/fetching
// method is known and required credentials are presented
// (such as a refresh token).
func (t *authorizedTransport) RefreshToken() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	token, err := t.fetcher.FetchToken(t.token)
	if err != nil {
		return err
	}
	t.token = token
	return nil
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header)
	for k, s := range r.Header {
		r2.Header[k] = s
	}
	return r2
}
