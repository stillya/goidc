package token

import (
	"errors"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stillya/goidc/logger"
	"os"
	"time"
)

type JWKService struct {
	keySet               jwk.Set
	publicKeySet         jwk.Set
	issuer               string
	accessTokenValidity  time.Duration
	refreshTokenValidity time.Duration
	logger               logger.L
}

type Opts struct {
	PrivateKeyPath       string
	PublicKeyPath        string
	Issuer               string
	AccessTokenLifetime  time.Duration
	RefreshTokenLifetime time.Duration
	Logger               logger.L
}

func NewJWKService(opts Opts) (*JWKService, error) {
	privateKeyFile, err := os.ReadFile(opts.PrivateKeyPath)
	publicKeyFile, err := os.ReadFile(opts.PublicKeyPath)
	if err != nil {
		return nil, err
	}

	keySet, err := parseKeySet(privateKeyFile, opts.PrivateKeyPath)
	if err != nil {
		return nil, err
	}

	publicKeySet, err := parseKeySet(publicKeyFile, opts.PublicKeyPath)
	if err != nil {
		return nil, err
	}

	return &JWKService{
		keySet:               *keySet,
		publicKeySet:         *publicKeySet,
		issuer:               opts.Issuer,
		accessTokenValidity:  opts.AccessTokenLifetime,
		refreshTokenValidity: opts.RefreshTokenLifetime,
		logger:               opts.Logger,
	}, nil
}

func (j *JWKService) GetPublicKeySet() jwk.Set {
	return j.publicKeySet
}

func (j *JWKService) BuildToken(subject string, metadata map[string]interface{}, tokenType string) (string, error) {
	if tokenType == "access_token" {
		return j.buildAccessToken(subject, metadata)
	} else if tokenType == "refresh_token" {
		return j.buildRefreshToken(subject, metadata)
	} else {
		return "", nil
	}
}

func (j *JWKService) ParseToken(token string) (*jwt.Token, error) {
	if j.publicKeySet == nil {
		return nil, nil
	}

	verifiedToken, err := jwt.Parse([]byte(token), jwt.WithKeySet(j.publicKeySet))

	return &verifiedToken, err
}

func (j *JWKService) buildAccessToken(subject string, metadata map[string]interface{}) (string, error) {
	if j.publicKeySet == nil {
		return "", nil
	}
	rsaKey, ok := j.keySet.Key(0)
	if !ok {
		return "", errors.New("key not found")
	}

	body := jwt.NewBuilder().
		JwtID(uuid.New().String()).
		Issuer(j.issuer).
		IssuedAt(time.Now().UTC()).
		NotBefore(time.Now().UTC()).
		Expiration(time.Now().UTC().Add(j.accessTokenValidity)).
		Subject(subject)
	for claimKey, claimVal := range metadata {
		body = body.Claim(claimKey, claimVal)
	}

	tok, err := body.Build()
	if err != nil {
		return "", err
	}

	signedToken, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, rsaKey))
	if err != nil {
		return "", err
	}

	return string(signedToken), nil
}

func (j *JWKService) buildRefreshToken(subject string, metadata map[string]interface{}) (string, error) {
	if j.publicKeySet == nil {
		return "", nil
	}
	rsaKey, ok := j.keySet.Key(0)
	if !ok {
		return "", errors.New("key not found")
	}

	body := jwt.NewBuilder().
		JwtID(uuid.New().String()).
		Issuer(j.issuer).
		IssuedAt(time.Now().UTC()).
		NotBefore(time.Now().UTC()).
		Expiration(time.Now().UTC().Add(j.refreshTokenValidity)).
		Subject(subject)

	for claimKey, claimVal := range metadata {
		body = body.Claim(claimKey, claimVal)
	}

	tok, err := body.Build()
	if err != nil {
		return "", err
	}

	signedToken, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, rsaKey))
	if err != nil {
		return "", err
	}

	return string(signedToken), nil
}

func parseKeySet(keyFile []byte, fileName string) (*jwk.Set, error) {
	if fileName[len(fileName)-5:] == ".jwks" {
		keySet, err := jwk.Parse(keyFile)
		if err != nil {
			return nil, err
		}
		return &keySet, nil
	} else if fileName[len(fileName)-4:] == ".pem" {
		keySet, err := jwk.Parse(keyFile, jwk.WithPEM(true))
		if err != nil {
			return nil, err
		}
		return &keySet, nil
	} else {
		return nil, errors.New("invalid file format")
	}
}
