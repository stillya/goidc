package provider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
)

type Provider struct {
	Params
	name                  string
	authorizationEndpoint string
	tokenEndpoint         string
	userinfoEndpoint      string
	jwksURI               string
	claimsSupported       []string

	client *http.Client
}

type Params struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type WellKnown struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	UserinfoEndpoint       string   `json:"userinfo_endpoint"`
	JwksURI                string   `json:"jwks_uri"`
	ClaimsSupported        []string `json:"claims_supported"`
	GrantTypesSupported    []string `json:"grant_types_supported"`
	ResponseTypesSupported []string `json:"response_types_supported"`
}

type UserInfo struct {
	Subject       string `json:"sub"`
	Profile       string `json:"profile"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`

	claims []byte
}

func InitProvider(ctx context.Context, params Params, name string) (*Provider, error) {
	c := getClient(ctx)

	wellKnownURL := params.Issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get well-known: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get well-known: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	var wellKnown WellKnown
	err = json.Unmarshal(body, &wellKnown)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal body: %w", err)
	}

	return &Provider{
		name:                  name,
		Params:                params,
		authorizationEndpoint: wellKnown.AuthorizationEndpoint,
		tokenEndpoint:         wellKnown.TokenEndpoint,
		userinfoEndpoint:      wellKnown.UserinfoEndpoint,
		jwksURI:               wellKnown.JwksURI,
		claimsSupported:       wellKnown.ClaimsSupported,
		client:                c,
	}, nil
}

func (p *Provider) Name() string {
	return p.name
}

func (p *Provider) LoginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := randToken(32)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "state",
		Value: state,
	})

	http.Redirect(w, r, p.authorizationEndpoint+"?response_type=code&client_id="+p.ClientID+"&state="+state+"&redirect_uri="+p.getRedirectURL()+"&scope=openid", http.StatusFound)
}

func (p *Provider) CallbackHandler(w http.ResponseWriter, r *http.Request) (map[string]interface{}, error) {
	state, err := r.Cookie("state")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return nil, fmt.Errorf("state not found")
	}

	if r.URL.Query().Get("state") != state.Value {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return nil, fmt.Errorf("state did not match")
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "code not found", http.StatusBadRequest)
		return nil, fmt.Errorf("code not found")
	}

	token, err := p.Exchange(code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	if token.AccessToken == "" {
		http.Error(w, "token not found", http.StatusBadRequest)
		return nil, fmt.Errorf("token not found")
	}

	u, err := p.UserInfo(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return nil, fmt.Errorf("failed to get userinfo: %w", err)
	}

	return u, nil
}

func (p *Provider) Exchange(code string) (*oauth2.Token, error) {
	v := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {p.ClientID},
		"client_secret": {p.ClientSecret},
		"redirect_uri":  {p.getRedirectURL()},
		"scope":         {"openid"},
	}

	resp, err := p.client.PostForm(p.tokenEndpoint, v)
	if err != nil {
		return nil, fmt.Errorf("failed to post form: %w", err)
	}

	defer resp.Body.Close()

	var token oauth2.Token
	err = json.NewDecoder(resp.Body).Decode(&token)
	if err != nil {
		return nil, fmt.Errorf("failed to decode body: %w", err)
	}

	return &token, nil
}

func (p *Provider) UserInfo(token *oauth2.Token) (map[string]interface{}, error) {
	req, err := http.NewRequest(http.MethodGet, p.userinfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get userinfo: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	var m map[string]interface{}
	err = json.Unmarshal(body, &m)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal body: %w", err)
	}

	return m, nil
}

func getClient(ctx context.Context) *http.Client {
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		return c
	} else {
		return http.DefaultClient
	}
}

func ClientContext(ctx context.Context, client *http.Client) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, client)
}

func randToken(size int) (string, error) {
	randBytes := make([]byte, size)
	_, err := rand.Read(randBytes)
	if err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(randBytes), nil
}

func (p *Provider) getRedirectURL() string {
	return p.RedirectURL + "?provider=" + p.name
}
