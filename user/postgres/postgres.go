package postgres

import (
	"context"
	"fmt"
	_ "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stillya/goidc/user"
)

type DB struct {
	pool *pgxpool.Pool
}

type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
}

func NewDB(c Config) (*DB, error) {
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", c.User, c.Password, c.Host, c.Port, c.Database)
	pool, err := pgxpool.New(context.Background(), connStr)
	if err != nil {
		return nil, fmt.Errorf("can't connect to db, %v", err)
	}
	return &DB{pool: pool}, nil
}

func (p *DB) FindUser(username string) (*user.User, error) {
	var u user.User
	err := p.pool.QueryRow(context.Background(), "SELECT user_id, username, attributes, disabled FROM users WHERE username = $1",
		username).Scan(&u.UserID, &u.Username, &u.Attributes, &u.Disabled)
	if err != nil {
		return nil, fmt.Errorf("can't find u, %v", err)
	}
	return &u, nil
}

func (p *DB) PutUser(u *user.User) error {
	_, err := p.pool.Exec(context.Background(), "INSERT INTO users (user_id, username, attributes, disabled) VALUES ($1, $2, $3, $4)",
		u.UserID, u.Username, u.Attributes, u.Disabled)
	if err != nil {
		return fmt.Errorf("can't insert u, %v", err)
	}
	return nil
}
