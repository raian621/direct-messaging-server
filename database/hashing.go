package database

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrIncompatableArgon2Version error = errors.New("incompatable argon2 version")
	ErrInvalidArgon2FieldCount   error = errors.New("invalid number of fields")
)

type Argon2Params struct {
	Version int
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
	Salt    []byte
	Key     []byte
}

func GenerateHash(secret string) (string, error) {
	var (
		salt    []byte = make([]byte, 16)
		time    uint32 = 1
		memory  uint32 = 64 * 1024
		threads uint8  = 4
		keyLen  uint32 = 32
	)
	if n, err := rand.Read(salt); err != nil {
		return "", err
	} else if n != len(salt) {
		return "", errors.New("random salt was not long enough")
	}
	key := argon2.IDKey([]byte(secret), salt, time, memory, threads, keyLen)
	passhash := fmt.Sprintf(
		"$argon2id$v=%d$t=%d,m=%d,p=%d$%s$%s",
		argon2.Version,
		time,
		memory,
		threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)

	return passhash, nil
}

func VerifyHash(secret, hash string) bool {
	var data Argon2Params
	if err := DecodeHash(hash, &data); err != nil {
		log.Printf("error verifying hash: %v", err)
		return false
	}

	secretHash := argon2.IDKey(
		[]byte(secret),
		[]byte(data.Salt),
		data.Time,
		data.Memory,
		data.Threads,
		data.KeyLen,
	)

	return reflect.DeepEqual(secretHash, data.Key)
}

func DecodeHash(hash string, data *Argon2Params) error {
	fields := strings.Split(hash, "$")
	if len(fields) != 6 {
		return ErrInvalidArgon2FieldCount
	}

	if fields[0] != "" || fields[1] != "argon2id" {
		return ErrIncompatableArgon2Version
	}

	if _, err := fmt.Sscanf(fields[2], "v=%d", &data.Version); err != nil {
		return err
	}

	if argon2.Version != data.Version {
		return ErrIncompatableArgon2Version
	}

	if _, err := fmt.Sscanf(
		fields[3],
		"t=%d,m=%d,p=%d",
		&data.Time,
		&data.Memory,
		&data.Threads,
	); err != nil {
		return err
	}

	var err error
	if data.Salt, err = base64.RawStdEncoding.DecodeString(fields[4]); err != nil {
		return err
	}
	if data.Key, err = base64.RawStdEncoding.DecodeString(fields[5]); err != nil {
		return err
	}
	data.KeyLen = uint32(len(data.Key))

	return nil
}
