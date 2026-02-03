package domain

type Client struct {
	ID            string   `yaml:"id"`
	Name          string   `yaml:"name"`
	RedirectUris  []string `yaml:"redirect_uris"`
	Public        bool     `yaml:"public"`
	AllowedScopes []string `yaml:"allowed_scopes"`
}
