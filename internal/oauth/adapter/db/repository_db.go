package db

import (
	"fmt"
	"os"
	"sync"

	"oauthmock/internal/oauth/domain"

	"gopkg.in/yaml.v3"
)

type Repository struct {
	mu      sync.RWMutex
	path    string
	clients []domain.Client
	byID    map[string]domain.Client
	byName  map[string]domain.Client
}

type clientsFile struct {
	Clients []domain.Client `yaml:"clients"`
}

func NewRepositoryFromYAML(path string) (*Repository, error) {
	repo := &Repository{path: path}
	if err := repo.Reload(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *Repository) Reload() error {
	data, err := os.ReadFile(r.path)
	if err != nil {
		return fmt.Errorf("read yaml file: %w", err)
	}

	var file clientsFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parse yaml file: %w", err)
	}

	byID := make(map[string]domain.Client, len(file.Clients))
	byName := make(map[string]domain.Client, len(file.Clients))
	for _, client := range file.Clients {
		if client.ID != "" {
			byID[client.ID] = client
		}
		if client.Name != "" {
			byName[client.Name] = client
		}
	}

	r.mu.Lock()
	r.clients = file.Clients
	r.byID = byID
	r.byName = byName
	r.mu.Unlock()

	return nil
}

func (r *Repository) Clients() []domain.Client {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]domain.Client, len(r.clients))
	copy(out, r.clients)
	return out
}

func (r *Repository) ClientByID(id string) (domain.Client, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	client, ok := r.byID[id]
	return client, ok
}

func (r *Repository) ClientByName(name string) (domain.Client, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	client, ok := r.byName[name]
	return client, ok
}
