package provider

import (
	"context"
	"fmt"
	keycloak "github.com/stillya/testcontainers-keycloak"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

var keycloakContainer *keycloak.KeycloakContainer

func Test_initProvider(t *testing.T) {
	authServerURL, err := keycloakContainer.GetAuthServerURL(context.Background())
	if err != nil {
		t.Errorf("Testcontainer error = %v", err)
		return
	}
	type args struct {
		ctx    context.Context
		params Params
	}
	tests := []struct {
		name    string
		args    args
		want    *Provider
		wantErr bool
	}{
		{
			name: "Test_initProvider",
			args: args{
				ctx: context.Background(),
				params: Params{
					Issuer:   authServerURL + "/realms/Test",
					ClientID: "test-app",
				},
			},
			want: &Provider{
				Params: Params{
					Issuer:   authServerURL,
					ClientID: "test-app",
				},
				authorizationEndpoint: authServerURL + "/realms/Test/protocol/openid-connect/auth",
				tokenEndpoint:         authServerURL + "/realms/Test/protocol/openid-connect/token",
				userinfoEndpoint:      authServerURL + "/realms/Test/protocol/openid-connect/userinfo",
				jwksURI:               authServerURL + "/realms/Test/protocol/openid-connect/certs",
				claimsSupported: []string{
					"aud",
					"sub",
					"iss",
					"auth_time",
					"name",
					"given_name",
					"family_name",
					"preferred_username",
					"email",
					"acr",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InitProvider(tt.args.ctx, tt.args.params, tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("initProvider() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.want.Equal(got) {
				t.Errorf("initProvider() got = %v, want %v", got, tt.want)
			}
			if got.Name() != tt.name {
				t.Errorf("initProvider() got = %v, want %v", got.Name(), tt.name)
			}
		})
	}
}

func TestProvider_LoginHandler(t *testing.T) {
	authServerURL, err := keycloakContainer.GetAuthServerURL(context.Background())
	if err != nil {
		t.Errorf("Testcontainer error = %v", err)
		return
	}
	type args struct {
		ctx    context.Context
		params Params
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Test_loginHandler",
			args: args{
				ctx: context.Background(),
				params: Params{
					Issuer:   authServerURL + "/realms/Test",
					ClientID: "test-app",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := InitProvider(tt.args.ctx, tt.args.params, tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("initProvider() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			req := httptest.NewRequest("GET", "http://oidc.dev/login", nil)
			w := httptest.NewRecorder()
			provider.LoginHandler(w, req)

			resp := w.Result()
			if resp.StatusCode != 302 {
				t.Errorf("LoginHandler() status code = %v, want %v", resp.StatusCode, 302)
			}
			if isWildcardMatch(resp.Header.Get("Location"), provider.authorizationEndpoint) {
				t.Errorf("LoginHandler() location = %v, want %v", resp.Header.Get("Location"), provider.authorizationEndpoint)
			}
		})
	}
}

// Lifecycle and utils

func TestMain(m *testing.M) {
	defer func() {
		if r := recover(); r != nil {
			shutDown()
			fmt.Println("Panic")
		}
	}()
	setup()
	code := m.Run()
	shutDown()
	os.Exit(code)
}

func setup() {
	var err error
	ctx := context.Background()
	keycloakContainer, err = RunKeycloakContainer(ctx)
	if err != nil {
		panic(err)
	}
}

func shutDown() {
	ctx := context.Background()
	err := keycloakContainer.Terminate(ctx)
	if err != nil {
		panic(err)
	}
}

func RunKeycloakContainer(ctx context.Context) (*keycloak.KeycloakContainer, error) {
	return keycloak.Run(ctx,
		"keycloak/keycloak:24.0",
		keycloak.WithContextPath("/auth"),
		keycloak.WithRealmImportFile("testdata/realm-export.json"),
		keycloak.WithAdminUsername("admin"),
		keycloak.WithAdminPassword("admin"),
	)
}

func (p *Provider) Equal(other *Provider) bool {
	return p.authorizationEndpoint == other.authorizationEndpoint &&
		p.tokenEndpoint == other.tokenEndpoint &&
		p.userinfoEndpoint == other.userinfoEndpoint &&
		p.jwksURI == other.jwksURI &&
		reflect.DeepEqual(p.claimsSupported, other.claimsSupported)
}

func isWildcardMatch(input, pattern string) bool {
	if strings.HasPrefix(input, pattern[:len(pattern)-1]) &&
		strings.HasSuffix(input, pattern[len(pattern)-1:]) {
		return true
	}
	return false
}
