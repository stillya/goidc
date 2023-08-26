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
	"github.com/stillya/goidc/provider"
	"github.com/stillya/goidc/user"
	"github.com/stillya/goidc/user/postgres"
	"net/http"
)

func main() {
	ctx := context.Background()

	mapUserFunc := func(u map[string]interface{}) (*user.User, error) {
		return &user.User{
			Username: u["preferred_username"].(string),
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

	params := provider.Params{
		Issuer:       "https://keycloak.com/realms/test",
		RedirectURL:  "http://localhost:8085/callback",
		ClientID:     "test",
		ClientSecret: "test",
	}

	g, err := goidc.NewService(
		goidc.Opts{
			UseAsymmetricEnc:     true,
			PublicKey:            "example/keycloak/testdata/public.jwks",
			PrivateKey:           "example/keycloak/testdata/private.jwks",
			Issuer:               "goidc",
			Audience:             "goidc",
			AccessTokenLifetime:  15,
			RefreshTokenLifetime: 24,
			UserStore:            userStore,
			MapUserFunc:          mapUserFunc,
		})

	err = g.AddProvider(ctx, params, "keycloak")
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/login", g.LoginHandler)
	http.HandleFunc("/callback", g.CallbackHandler)
	http.HandleFunc("/certs", g.PublicKeySetHandler)

	err = http.ListenAndServe(":8085", nil)
	if err != nil {
		panic(err)
	}
}
```



