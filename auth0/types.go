package auth0

import "errors"

type Config struct {
	Domain       string `mapstructure:"domain"`
	ClientId     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	CallbackUrl  string `mapstructure:"callback_url"`
	LogoutUrl    string `mapstructure:"logout_url"`
	DbConnection string `mapstructure:"db_connection"`
}

func (c *Config) Check() (bool, error) {
	if c.Domain == "" {
		return false, errors.New("domain cannot be null")
	}
	if c.ClientId == "" {
		return false, errors.New("client_id cannot be null")
	}
	if c.ClientSecret == "" {
		return false, errors.New("client_secret cannot be null")
	}
	if c.CallbackUrl == "" {
		return false, errors.New("callback_url cannot be null")
	}
	return true, nil
}
