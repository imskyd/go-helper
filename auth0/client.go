package auth0

import (
	"context"
	"errors"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Authenticator is used to authenticate our users.
type Authenticator struct {
	*oidc.Provider
	oauth2.Config
}

// New instantiates the *Authenticator.
func NewAuthenticator(domain string, clientId string, clientSecret string, callbackURL string) (*Authenticator, error) {
	provider, err := oidc.NewProvider(
		context.Background(),
		"https://"+domain+"/",
	)
	if err != nil {
		return nil, err
	}

	conf := oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		RedirectURL:  callbackURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
	}

	return &Authenticator{
		Provider: provider,
		Config:   conf,
	}, nil
}

// VerifyIDToken verifies that an *oauth2.Token is a valid *oidc.IDToken.
func (a *Authenticator) VerifyIDToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("no id_token field in oauth2 token")
	}

	oidcConfig := &oidc.Config{
		ClientID: a.ClientID,
	}

	return a.Verifier(oidcConfig).Verify(ctx, rawIDToken)
}

func (a *Authenticator) GetAuthCodeURL(state string) string {
	return a.AuthCodeURL(state)
}

func (a *Authenticator) GetProfileFromCode(ctx context.Context, code string) (map[string]interface{}, *oauth2.Token, error) {
	// Exchange an authorization code for a token.
	token, err := a.Exchange(ctx, code)
	if err != nil {
		return nil, nil, errors.New("Failed to convert an authorization code into a token.")
	}

	idToken, err := a.VerifyIDToken(ctx, token)
	if err != nil {
		return nil, nil, errors.New("Failed to verify ID Token.")
	}

	var profile map[string]interface{}
	if err := idToken.Claims(&profile); err != nil {
		return nil, nil, errors.New("Failed to claim profile from idToken")
	}
	return profile, token, nil
}
