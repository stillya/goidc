package provider

import (
	"context"
	"reflect"
	"testing"
)

func Test_initProvider(t *testing.T) {
	t.SkipNow()
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
					// TODO: change issuer and clientID
					Issuer:   "https://keycloak.com/realms/test",
					ClientID: "test",
				},
			},
			want: &Provider{
				Params: Params{
					Issuer:   "https://keycloak.com/realms/test",
					ClientID: "test",
				},
				authorizationEndpoint: "https://keycloak.com/realms/test/protocol/openid-connect/auth",
				tokenEndpoint:         "https://keycloak.com/realms/test/protocol/openid-connect/token",
				userinfoEndpoint:      "https://keycloak.com/realms/test/protocol/openid-connect/userinfo",
				jwksURI:               "https://keycloak.com/realms/test/protocol/openid-connect/certs",
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
		})
	}
}

func (p *Provider) Equal(other *Provider) bool {
	return p.authorizationEndpoint == other.authorizationEndpoint &&
		p.tokenEndpoint == other.tokenEndpoint &&
		p.userinfoEndpoint == other.userinfoEndpoint &&
		p.jwksURI == other.jwksURI &&
		reflect.DeepEqual(p.claimsSupported, other.claimsSupported)
}
