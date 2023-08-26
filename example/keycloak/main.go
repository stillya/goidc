package main

import (
	"context"
	"fmt"
	"github.com/stillya/goidc"
	"github.com/stillya/goidc/user"
	"github.com/stillya/goidc/user/postgres"
	"net/http"
	"time"
)

func main() {
	ctx := context.Background()

	mapUserFunc := func(u map[string]interface{}) (*user.User, error) {
		return &user.User{
			UserID:     u["sub"].(string),
			Username:   u["preferred_username"].(string),
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
			PublicKey:            "example/keycloak/testdata/public.jwks",
			PrivateKey:           "example/keycloak/testdata/private.jwks",
			Issuer:               "goidc",
			Audience:             "goidc",
			AccessTokenLifetime:  time.Minute * 15,
			RefreshTokenLifetime: time.Hour * 24,
			UserStore:            userStore,
			MapUserFunc:          mapUserFunc,
		})

	err = g.AddProvider(ctx, "https://keycloak.com/realms/test",
		"keycloak", "test", "test-client")
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

	fmt.Println("Server started at http://localhost:8085")
	err = http.ListenAndServe(":8085", nil)
	if err != nil {
		panic(err)
	}
}
