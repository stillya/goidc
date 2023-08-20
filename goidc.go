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
}

type UserStore interface {
	FindUser(username string) (*user.User, error)
	PutUser(username string) error
}

type Provider interface {
	Name() string
	LoginHandler(w http.ResponseWriter, r *http.Request)
	CallbackHandler(w http.ResponseWriter, r *http.Request) (map[string]interface{}, error)
}

type Service struct {
	opts         Opts
	tokenService TokenService
	userStore    UserStore
	providers    map[string]Provider
	mapUserFunc  func(u map[string]interface{}) (*user.User, error)
	logger       logger.L
}

type Opts struct {
	UseAsymmetricEnc bool
	PublicKey        string
	PrivateKey       string
	SymmetricKey     string

	Issuer   string
	Audience string

	AccessTokenLifetime  time.Duration
	RefreshTokenLifetime time.Duration

	UserStore   UserStore
	MapUserFunc func(u map[string]interface{}) (*user.User, error)

	logger logger.L
}

func NewService(opts Opts) (*Service, error) {
	if opts.logger == nil {
		opts.logger = logger.Std
	}

	s := &Service{
		opts:        opts,
		logger:      opts.logger,
		userStore:   opts.UserStore,
		mapUserFunc: opts.MapUserFunc,
		providers:   make(map[string]Provider),
	}

	if opts.UseAsymmetricEnc {
		tokenService, err := token.NewJWKService(token.Opts{
			PrivateKeyPath:       opts.PrivateKey,
			PublicKeyPath:        opts.PublicKey,
			Issuer:               opts.Issuer,
			AccessTokenLifetime:  opts.AccessTokenLifetime,
			RefreshTokenLifetime: opts.RefreshTokenLifetime,
			Logger:               opts.logger,
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

func (s *Service) AddProvider(ctx context.Context, params provider.Params, name string) error {
	p, err := provider.InitProvider(ctx, params, name)
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
		return
	}

	p, err := s.GetProvider(providerName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	u, err := p.CallbackHandler(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	mappedUser, err := s.mapUserFunc(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, err := s.userStore.FindUser(mappedUser.Username); err != nil {
		err = s.userStore.PutUser(mappedUser.Username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	accessToken, err := s.tokenService.BuildToken(mappedUser.Username, u, "access_token")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	refreshToken, err := s.tokenService.BuildToken(mappedUser.Username, u, "refresh_token")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	accessTokenCookie := http.Cookie{Name: "access_token", Value: accessToken, Expires: time.Now().Add(s.opts.AccessTokenLifetime)}
	refreshTokenCookie := http.Cookie{Name: "refresh_token", Value: refreshToken, Expires: time.Now().Add(s.opts.RefreshTokenLifetime)}

	http.SetCookie(w, &accessTokenCookie)
	http.SetCookie(w, &refreshTokenCookie)

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
