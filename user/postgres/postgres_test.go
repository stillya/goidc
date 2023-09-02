package postgres

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stillya/goidc/user"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var container *postgres.PostgresContainer

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

func TestNewDB(t *testing.T) {
	err := recreateDB(context.Background(), container, filepath.Join("testdata", "init.sql"))
	if err != nil {
		t.Errorf("RecreateDB() error = %v", err)
		return
	}

	host, err := container.Host(context.Background())
	if err != nil {
		t.Errorf("Host() error = %v", err)
		return
	}
	port, err := container.MappedPort(context.Background(), "5432")
	if err != nil {
		t.Errorf("MappedPort() error = %v", err)
		return
	}

	type args struct {
		c Config
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "TestNewDB",
			args: args{c: Config{
				Host:     host,
				Port:     port.Int(),
				User:     "postgres",
				Password: "postgres",
				Database: "goidc",
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewDB(tt.args.c)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDB() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestDB_FindUser(t *testing.T) {
	err := recreateDB(context.Background(), container, filepath.Join("testdata", "init.sql"))
	if err != nil {
		t.Errorf("RecreateDB() error = %v", err)
		return
	}

	host, err := container.Host(context.Background())
	if err != nil {
		t.Errorf("Host() error = %v", err)
		return
	}
	port, err := container.MappedPort(context.Background(), "5432")
	if err != nil {
		t.Errorf("MappedPort() error = %v", err)
		return
	}

	db, err := NewDB(Config{
		Host:     host,
		Port:     port.Int(),
		User:     "postgres",
		Password: "postgres",
		Database: "goidc",
	})
	if err != nil {
		t.Errorf("NewDB() error = %v", err)
		return
	}

	_, err = db.pool.Exec(context.Background(), "INSERT INTO users (user_id, username, attributes, disabled) VALUES ($1, $2, $3, $4)",
		"test", "test", "{}", false)

	type args struct {
		username string
	}

	tests := []struct {
		name    string
		args    args
		want    *user.User
		wantErr bool
	}{
		{
			name: "TestDB_FindUser",
			args: args{username: "test"},
			want: &user.User{
				UserID: "test",
			},
		},
		{
			name:    "TestDB_FindUser_not_found",
			args:    args{username: "test_not_found"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := db.FindUser(tt.args.username)
			if tt.wantErr {
				if err == nil {
					t.Errorf("FindUser() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if got.UserID != tt.want.UserID {
				t.Errorf("FindUser() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDB_PutUser(t *testing.T) {
	err := recreateDB(context.Background(), container, filepath.Join("testdata", "init.sql"))
	if err != nil {
		t.Errorf("RecreateDB() error = %v", err)
		return
	}

	host, err := container.Host(context.Background())
	if err != nil {
		t.Errorf("Host() error = %v", err)
		return
	}
	port, err := container.MappedPort(context.Background(), "5432")
	if err != nil {
		t.Errorf("MappedPort() error = %v", err)
		return
	}

	db, err := NewDB(Config{
		Host:     host,
		Port:     port.Int(),
		User:     "postgres",
		Password: "postgres",
		Database: "goidc",
	})
	if err != nil {
		t.Errorf("NewDB() error = %v", err)
		return
	}

	type args struct {
		u *user.User
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "TestDB_PutUser",
			args: args{u: &user.User{
				UserID:     "test",
				Username:   "test",
				Attributes: make(map[string]interface{}),
				Disabled:   false,
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err = db.PutUser(tt.args.u)
			if err != nil {
				t.Errorf("PutUser() error = %v", err)
				return
			}
		})
	}
}

func setup() {
	var err error
	ctx := context.Background()
	container, err = RunContainer(ctx)
	if err != nil {
		panic(err)
	}
}

func shutDown() {
	ctx := context.Background()
	err := container.Terminate(ctx)
	if err != nil {
		panic(err)
	}
}

func RunContainer(ctx context.Context) (*postgres.PostgresContainer, error) {
	return postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:13"),
		postgres.WithInitScripts(filepath.Join("testdata", "init.sql")),
		postgres.WithDatabase("goidc"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(5*time.Second)),
	)
}

func recreateDB(ctx context.Context, container *postgres.PostgresContainer, initScriptPath string) error {
	host, err := container.Host(ctx)
	if err != nil {
		return err
	}
	port, err := container.MappedPort(ctx, "5432")
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", "postgres", "postgres", host, port.Int(), "goidc")

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return fmt.Errorf("can't connect to db, %v", err)
	}

	_, err = pool.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
	if err != nil {
		return fmt.Errorf("can't drop schema, %v", err)
	}

	query, err := os.ReadFile(initScriptPath)
	if err != nil {
		return fmt.Errorf("can't read init script, %v", err)
	}

	_, err = pool.Exec(ctx, string(query))
	if err != nil {
		return fmt.Errorf("can't init schema, %v", err)
	}

	return nil
}
