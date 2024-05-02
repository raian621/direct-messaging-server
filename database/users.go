package database

import (
	"context"

	"github.com/google/uuid"
)

func CreateUser(data struct {
	Username string
	Email    string
	Password string
}) error {
	passhash, err := GenerateHash(data.Password)
	if err != nil {
		return err
	}

	_, err = dbpool.Exec(
		context.Background(),
		"INSERT INTO users (id, username, email, passhash) VALUES ($1, $2, $3, $4)",
		uuid.New(),
		data.Username,
		data.Email,
		passhash,
	)
	if err != nil {
		return err
	}

	return nil
}
