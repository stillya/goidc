# goidc - authentication with OpenID Connect

This package provides a simple way to authenticate users with OpenID Connect and help you to create an authentication service.

### NOTE: This package is still in development and not ready for production use.

* Support for different OpenID Connect providers(currently tested with Keycloak and Google, but should work with any other providers)
* Support for different authentication flows (currently tested with Authorization Code Flow, but others in progress)
* JWKS and PEM key support.
* Custom storage for users. Default is PostgreSQL, but you can implement your own storage.

## Installation

```bash
go get github.com/stillya/goidc
```

## Usage

### Create a new client

```go
package main

import (
	"context"
	"github.com/stillya/goidc"
	"github.com/stillya/goidc/user"
	"github.com/stillya/goidc/user/postgres"
	"net/http"
	"time"
)

func main() {
	ctx := context.Background()

	keycloakMapUserFunc := func(u map[string]interface{}) (*user.User, error) {
		return &user.User{
			UserID:     u["sub"].(string),
			Username:   u["preferred_username"].(string),
			Attributes: u,
		}, nil
	}

	googleMapUserFunc := func(u map[string]interface{}) (*user.User, error) {
		return &user.User{
			UserID:     u["sub"].(string),
			Username:   u["name"].(string),
			Attributes: u,
		}, nil
	}

	userStore, err := postgres.NewDB(postgres.Config{
		Host:     "localhost",
		Port:     5432,
		User:     "postgres",
		Password: "postgres",
		Database: "oidc",
	})
	if err != nil {
		panic(err)
	}

	g, err := goidc.NewService(
		goidc.Opts{
			BaseURL:              "http://localhost:8085",
			UseAsymmetricEnc:     true,
			PublicKey:            "example/testdata/public.jwks",
			PrivateKey:           "example/testdata/private.jwks",
			Issuer:               "goidc",
			Audience:             "goidc",
			AccessTokenLifetime:  time.Minute * 15,
			RefreshTokenLifetime: time.Hour * 24,
			UserStore:            userStore,
		})

	err = g.AddProvider(ctx,
		goidc.ProviderParams{
			Issuer:       "https://keycloak.com/realms/test",
			ClientID:     "test",
			ClientSecret: "test",
			MapUserFunc:  keycloakMapUserFunc,
			Scopes:       []string{"openid", "profile", "email"},
		}, "keycloak")
	if err != nil {
		panic(err)
	}

	err = g.AddProvider(ctx,
		goidc.ProviderParams{
			Issuer:       "https://accounts.google.com",
			ClientID:     "test",
			ClientSecret: "test",
			MapUserFunc:  googleMapUserFunc,
			Scopes:       []string{"openid", "profile", "email"},
		}, "google")
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/login", g.LoginHandler)
	http.HandleFunc("/callback", g.CallbackHandler)
	http.HandleFunc("/certs", g.PublicKeySetHandler)
	http.HandleFunc("/example", func(w http.ResponseWriter, r *http.Request) {
		accessToken, err := r.Cookie("ACCESS_TOKEN")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		refreshToken, err := r.Cookie("REFRESH_TOKEN")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("access_token: " + accessToken.Value + "\n"))
		_, _ = w.Write([]byte("refresh_token: " + refreshToken.Value + "\n"))
	})

	err = http.ListenAndServe(":8085", nil)
	if err != nil {
		panic(err)
	}
}
```



