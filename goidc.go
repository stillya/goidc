package goidc

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stillya/goidc/logger"
	"github.com/stillya/goidc/provider"
	"github.com/stillya/goidc/token"
	"github.com/stillya/goidc/user"
	"net/http"
	"time"
)

type TokenService interface {
	GetPublicKeySet() jwk.Set // only for asymmetric encryption
	BuildToken(subject string, metadata map[string]interface{}, tokenType string) (string, error)
	ParseToken(token string) (*jwt.Token, error)
	RenewToken(refreshToken string) (string, error)
}

type UserStore interface {
	FindUser(username string) (*user.User, error)
	PutUser(user *user.User) error
}

type Provider interface {
	Name() string
	LoginHandler(w http.ResponseWriter, r *http.Request)
	CallbackHandler(w http.ResponseWriter, r *http.Request)
}

type Service struct {
	opts         Opts
	tokenService TokenService
	providers    map[string]Provider

	logger.L
}

type Opts struct {
	BaseURL string

	UseAsymmetricEnc bool
	PublicKey        string
	PrivateKey       string
	SymmetricKey     string

	Issuer   string
	Audience string

	AccessTokenLifetime  time.Duration
	RefreshTokenLifetime time.Duration

	DisableXSRF bool

	AccessTokenCookieName  string // default: ACCESS_TOKEN
	RefreshTokenCookieName string // default: REFRESH_TOKEN
	XSRFCookieName         string // default: XSRF_TOKEN

	MapUserFunc func(u map[string]interface{}) (*user.User, error)

	UserStore UserStore

	logger.L
}

func NewService(opts Opts) (*Service, error) {
	if opts.L == nil {
		opts.L = logger.Std
	}

	s := &Service{
		opts:      opts,
		providers: make(map[string]Provider),
		L:         opts.L,
	}

	if opts.UseAsymmetricEnc {
		tokenService, err := token.NewJWKService(token.Opts{
			PrivateKeyPath:       opts.PrivateKey,
			PublicKeyPath:        opts.PublicKey,
			Issuer:               opts.Issuer,
			AccessTokenLifetime:  opts.AccessTokenLifetime,
			RefreshTokenLifetime: opts.RefreshTokenLifetime,
			L:                    opts.L,
		})
		if err != nil {
			return nil, err
		}
		s.tokenService = tokenService
	} else {
		panic("not implemented")
	}

	return s, nil
}

func (s *Service) AddProvider(ctx context.Context, issuer, name, clientSecret, clientID string) error {
	p, err := provider.InitProvider(ctx,
		provider.Params{
			BaseURL:                s.opts.BaseURL,
			Issuer:                 issuer,
			ClientID:               clientID,
			ClientSecret:           clientSecret,
			DisableXSRF:            s.opts.DisableXSRF,
			AccessTokenCookieName:  s.opts.AccessTokenCookieName,
			RefreshTokenCookieName: s.opts.RefreshTokenCookieName,
			XSRFCookieName:         s.opts.XSRFCookieName,
			UserStore:              s.opts.UserStore,
			MapUserFunc:            s.opts.MapUserFunc,
			TokenService:           s.tokenService,
			L:                      s.L,
		}, name)
	if err != nil {
		return err
	}

	s.providers[name] = p
	return nil
}

func (s *Service) GetProvider(name string) (Provider, error) {
	for _, p := range s.providers {
		if p.Name() == name {
			return p, nil
		}
	}
	return nil, fmt.Errorf("provider %s not found", name)
}

func (s *Service) LoginHandler(w http.ResponseWriter, r *http.Request) {
	providerName := r.URL.Query().Get("provider")
	if providerName == "" {
		http.Error(w, "provider not found", http.StatusBadRequest)
		return
	}

	p, err := s.GetProvider(providerName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	p.LoginHandler(w, r)
}

func (s *Service) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	providerName := r.URL.Query().Get("provider")
	if providerName == "" {
		http.Error(w, "provider not found", http.StatusBadRequest)
		s.Logf("[ERROR] provider not found")
		return
	}

	p, err := s.GetProvider(providerName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		s.Logf("[ERROR] failed to get provider: %s", err)
		return
	}

	p.CallbackHandler(w, r)
}

func (s *Service) PublicKeySetHandler(w http.ResponseWriter, _ *http.Request) {
	publicKeySet := s.tokenService.GetPublicKeySet()
	if publicKeySet == nil {
		http.Error(w, "public key set not found", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	publicKeySetJSON, err := json.Marshal(publicKeySet)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err = w.Write(publicKeySetJSON)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
}
