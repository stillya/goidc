package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stillya/goidc/logger"
	"github.com/stillya/goidc/user"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const stateCookieTimeout = time.Minute * 15
const defaultAccessCookieName = "ACCESS_TOKEN"
const defaultRefreshCookieName = "REFRESH_TOKEN"
const handshakeStateCookieName = "_COOKIE_STATE"
const defaultXSRFCookieName = "XSRF_TOKEN"

type TokenService interface {
	BuildToken(subject string, metadata map[string]interface{}, tokenType string) (string, error)
	ParseToken(token string) (jwt.Token, error)
}

type UserStore interface {
	FindUser(username string) (*user.User, error)
	PutUser(user *user.User) error
}

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
	BaseURL      string
	Issuer       string
	ClientID     string
	ClientSecret string

	DisableXSRF bool

	AccessTokenCookieName  string
	RefreshTokenCookieName string
	XSRFCookieName         string

	UserStore    UserStore
	TokenService TokenService

	MapUserFunc func(u map[string]interface{}) (*user.User, error)

	Scopes []string

	logger.L
}

type HandshakeState struct {
	From       string
	ProviderID string
	CSRFToken  string
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

	wellKnownURL := strings.TrimSuffix(params.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get well-known: %w", err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			params.Logf("[WARN] failed to close response body, %s", err)
		}
	}(resp.Body)

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

	if params.AccessTokenCookieName == "" {
		params.AccessTokenCookieName = defaultAccessCookieName
	}
	if params.RefreshTokenCookieName == "" {
		params.RefreshTokenCookieName = defaultRefreshCookieName
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
	from := r.URL.Query().Get("from")

	state, err := p.setProviderState(w, &HandshakeState{
		From:       from,
		ProviderID: p.name,
		CSRFToken:  "test",
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		p.Logf("[ERROR] failed to set provider state: %s", err)
		return
	}

	http.Redirect(w, r, p.authorizationEndpoint+"?response_type=code&client_id="+p.ClientID+"&state="+state+
		"&redirect_uri="+p.getRedirectURL()+"&scope="+p.getScopes(), http.StatusFound)
}

func (p *Provider) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	state, encState, err := p.getProviderState(r)
	if err != nil {
		p.Logf("[ERROR] failed to get provider state: %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if r.URL.Query().Get("state") != encState {
		p.Logf("[ERROR] state did not match")
		http.Error(w, "state did not match", http.StatusForbidden)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		p.Logf("[ERROR] code not found")
		http.Error(w, "code not found", http.StatusBadRequest)
		return
	}

	token, err := p.Exchange(code)
	if err != nil {
		p.Logf("[ERROR] failed to exchange code: %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if token.AccessToken == "" {
		p.Logf("[ERROR] token not found")
		http.Error(w, "token not found", http.StatusBadRequest)
		return
	}

	u, err := p.UserInfo(token)
	if err != nil {
		p.Logf("[ERROR] failed to get user info: %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err != nil {
		p.Logf("[ERROR] failed to get user info: %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	mappedUser, err := p.MapUserFunc(u)
	if err != nil {
		p.Logf("[ERROR] failed to map user: %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, err := p.UserStore.FindUser(mappedUser.Username); err != nil {
		err = p.UserStore.PutUser(mappedUser)
		if err != nil {
			p.Logf("[ERROR] failed to put user: %s", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	accessToken, err := p.TokenService.BuildToken(mappedUser.Username, u, "access_token")
	if err != nil {
		p.Logf("[ERROR] failed to build access token: %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	refreshToken, err := p.TokenService.BuildToken(mappedUser.Username, u, "refresh_token")
	if err != nil {
		p.Logf("[ERROR] failed to build refresh token: %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	accessTokenCookie := http.Cookie{Name: p.AccessTokenCookieName, Value: accessToken, Path: "/"}
	refreshTokenCookie := http.Cookie{Name: p.RefreshTokenCookieName, Value: refreshToken, Path: "/"}

	http.SetCookie(w, &accessTokenCookie)
	http.SetCookie(w, &refreshTokenCookie)

	if state.From != "" {
		http.Redirect(w, r, state.From, http.StatusFound)
	} else {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(fmt.Sprintf("%+v", u)))
	}
}

func (p *Provider) Exchange(code string) (*oauth2.Token, error) {
	v := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {p.ClientID},
		"client_secret": {p.ClientSecret},
		"redirect_uri":  {p.getRedirectURL()},
		"scope":         {p.getScopes()},
	}

	resp, err := p.client.PostForm(p.tokenEndpoint, v)
	if err != nil {
		return nil, fmt.Errorf("failed to post form: %w", err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			p.Logf("[WARN] failed to close response body, %s", err)
		}
	}(resp.Body)

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

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			p.Logf("[WARN] failed to close response body, %s", err)
		}
	}(resp.Body)

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

func (p *Provider) getRedirectURL() string {
	return strings.TrimSuffix(p.BaseURL, "/") + "/callback" + "?provider=" + p.name
}

func (p *Provider) getProviderState(r *http.Request) (*HandshakeState, string, error) {
	cookie, err := r.Cookie(strings.ToUpper(p.name) + handshakeStateCookieName)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get cookie: %w", err)
	}

	state := &HandshakeState{}
	err = state.Decode(cookie.Value)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode state: %w", err)
	}

	return state, cookie.Value, nil
}

func (p *Provider) setProviderState(w http.ResponseWriter, state *HandshakeState) (string, error) {
	encState := state.Encode()
	http.SetCookie(w, &http.Cookie{
		Name:    strings.ToUpper(p.name) + handshakeStateCookieName,
		Value:   encState,
		Path:    "/",
		Expires: time.Now().Add(stateCookieTimeout),
	})

	return encState, nil
}

func (p *Provider) getScopes() string {
	return strings.Join(p.Scopes, " ")
}

func (s *HandshakeState) Encode() string {
	b, _ := json.Marshal(s)
	return base64.URLEncoding.EncodeToString(b)
}

func (s *HandshakeState) Decode(str string) error {
	b, err := base64.URLEncoding.DecodeString(str)
	if err != nil {
		return err
	}

	err = json.Unmarshal(b, s)
	if err != nil {
		return err
	}

	return nil
}
