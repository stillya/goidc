package token

import (
	"testing"
	"time"
)

func TestJWKService_BuildToken(t *testing.T) {
	type args struct {
		privateKeyPath string
		publicKeyPath  string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "TestJWKService_BuildAccessToken_jwks",
			args: args{
				privateKeyPath: "testdata/private.jwks",
				publicKeyPath:  "testdata/public.jwks",
			},
		},
		{
			name: "TestJWKService_BuildToken_pem",
			args: args{
				privateKeyPath: "testdata/private.pem",
				publicKeyPath:  "testdata/public.pem",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwtService, err := NewJWKService(Opts{
				PrivateKeyPath:       tt.args.privateKeyPath,
				PublicKeyPath:        tt.args.publicKeyPath,
				Issuer:               "goidc",
				AccessTokenLifetime:  15 * time.Minute,
				RefreshTokenLifetime: 24 * time.Hour,
			})
			if err != nil {
				t.Errorf("NewJWKService() error = %v", err)
				return
			}

			actualToken, err := jwtService.BuildToken("goidc", map[string]interface{}{"sub": "goidc"}, "access_token")
			if err != nil {
				t.Errorf("BuildToken() error = %v", err)
				return
			}

			if actualToken == "" {
				t.Errorf("BuildToken() error = %v", err)
				return
			}
		})
	}
}

func TestJWKService_ParseToken(t *testing.T) {
	type args struct {
		privateKeyPath string
		publicKeyPath  string
		tokenType      string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "TestJWKService_BuildToken_jwks",
			args: args{
				privateKeyPath: "testdata/private.jwks",
				publicKeyPath:  "testdata/public.jwks",
				tokenType:      "access_token",
			},
		},
		{
			name: "TestJWKService_BuildToken_jwks",
			args: args{
				privateKeyPath: "testdata/private.jwks",
				publicKeyPath:  "testdata/public.jwks",
				tokenType:      "refresh_token",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwtService, err := NewJWKService(Opts{
				PrivateKeyPath:       tt.args.privateKeyPath,
				PublicKeyPath:        tt.args.publicKeyPath,
				Issuer:               "goidc",
				AccessTokenLifetime:  15 * time.Minute,
				RefreshTokenLifetime: 24 * time.Hour,
			})
			if err != nil {
				t.Errorf("NewJWKService() error = %v", err)
				return
			}

			token, err := jwtService.BuildToken("goidc", map[string]interface{}{"sub": "goidc"}, tt.args.tokenType)

			if err != nil {
				t.Errorf("BuildToken() error = %v", err)
				return
			}

			if token == "" {
				t.Errorf("BuildToken() error = %v", err)
				return
			}

			verifiedToken, err := jwtService.ParseToken(token)

			if err != nil {
				t.Errorf("ParseToken() error = %v", err)
				return
			}

			if verifiedToken == nil {
				t.Errorf("ParseToken() error = %v", err)
				return
			}
		})
	}
}

func TestJWKService_GetPublicKeySet(t *testing.T) {
	type args struct {
		privateKeyPath string
		publicKeyPath  string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "TestJWKService_GetPublicKeySet_jwks",
			args: args{
				privateKeyPath: "testdata/private.jwks",
				publicKeyPath:  "testdata/public.jwks",
			},
		},
		{
			name: "TestJWKService_GetPublicKeySet_pem",
			args: args{
				privateKeyPath: "testdata/private.pem",
				publicKeyPath:  "testdata/public.pem",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwtService, err := NewJWKService(Opts{
				PrivateKeyPath:       tt.args.privateKeyPath,
				PublicKeyPath:        tt.args.publicKeyPath,
				Issuer:               "goidc",
				AccessTokenLifetime:  15 * time.Minute,
				RefreshTokenLifetime: 24 * time.Hour,
			})
			if err != nil {
				t.Errorf("NewJWKService() error = %v", err)
				return
			}

			publicKeySet := jwtService.GetPublicKeySet()

			if publicKeySet == nil {
				t.Errorf("GetPublicKeySet() error = %v", err)
				return
			}
		})
	}
}

func TestJWKService_RenewToken(t *testing.T) {
	jwtService, err := NewJWKService(Opts{
		PrivateKeyPath:       "testdata/private.jwks",
		PublicKeyPath:        "testdata/public.jwks",
		Issuer:               "goidc",
		AccessTokenLifetime:  15 * time.Minute,
		RefreshTokenLifetime: 24 * time.Hour,
	})
	if err != nil {
		t.Errorf("NewJWKService() error = %v", err)
		return
	}

	accessToken, err := jwtService.BuildToken("goidc", map[string]interface{}{}, "access_token")
	if err != nil {
		t.Errorf("BuildToken() error = %v", err)
		return
	}

	if accessToken == "" {
		t.Errorf("BuildToken() error = %v", err)
		return
	}

	parsedAccessToken, err := jwtService.ParseToken(accessToken)

	time.Sleep(1 * time.Second)

	renewedAccessToken, err := jwtService.RenewToken(accessToken)

	if err != nil {
		t.Errorf("RenewToken() error = %v", err)
		return
	}

	parsedRenewedAccessToken, err := jwtService.ParseToken(renewedAccessToken)
	if err != nil {
		t.Errorf("ParseToken() error = %v", err)
		return
	}

	if parsedAccessToken.Expiration().Unix() >= parsedRenewedAccessToken.Expiration().Unix() {
		t.Errorf("RenewToken() error = %v", err)
		return
	}
}
