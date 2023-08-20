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
