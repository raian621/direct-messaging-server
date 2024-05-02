package database_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"testing"

	"github.com/raian621/direct-messaging-server/database"
	"golang.org/x/crypto/argon2"
)

func TestGenerateHash(t *testing.T) {
	t.Parallel()

	secret := "very_secret_password123"
	hash, err := database.GenerateHash(secret)
	if err != nil {
		t.Fatal(err)
	}

	pattern := fmt.Sprintf(
		"\\$argon2id\\$v=%d\\$t=[0-9]+,m=[0-9]+,p=[0-9]+\\$.+\\$.+",
		argon2.Version,
	)
	if matched, err := regexp.Match(
		pattern,
		[]byte(hash),
	); err != nil {
		t.Fatal(err)
	} else if !matched {
		t.Fatalf("hash '%s' did not match regex '%s'", hash, pattern)
	}
}

func TestDecodeHash(t *testing.T) {
	testCases := []struct {
		name     string
		hash     string
		wantData database.Argon2Params
		wantErr  error
	}{
		{
			name: "correct hash",
			hash: "$argon2id$v=19$t=1,m=65536,p=4$+so9Aocgsy068HEhWbi5Kg$PgNgX4shYkTGSWkkpD2U0whRnvz2ltcoPH4dwRG8kvg",
			wantData: database.Argon2Params{
				Version: 19,
				Time:    1,
				Memory:  65536,
				Threads: 4,
				Salt:    []byte("+so9Aocgsy068HEhWbi5Kg"),
				Key:     []byte("PgNgX4shYkTGSWkkpD2U0whRnvz2ltcoPH4dwRG8kvg"),
			},
		},
		{
			name:    "missing field",
			hash:    "$v=19$t=1,m=65536,p=4$+so9Aocgsy068HEhWbi5Kg$PgNgX4shYkTGSWkkpD2U0whRnvz2ltcoPH4dwRG8kvg",
			wantErr: database.ErrInvalidArgon2FieldCount,
		},
		{
			name:    "incorrect argon variant",
			hash:    "$argon2i$v=19$t=1,m=65536,p=4$+so9Aocgsy068HEhWbi5Kg$PgNgX4shYkTGSWkkpD2U0whRnvz2ltcoPH4dwRG8kvg",
			wantErr: database.ErrIncompatableArgon2Version,
		},
		{
			name:    "incorrect argon version",
			hash:    "$argon2id$v=69$t=1,m=65536,p=4$+so9Aocgsy068HEhWbi5Kg$PgNgX4shYkTGSWkkpD2U0whRnvz2ltcoPH4dwRG8kvg",
			wantErr: database.ErrIncompatableArgon2Version,
		},
		{
			name:    "incorrect hash start",
			hash:    "asdf$argon2id$v=19$t=1,m=65536,p=4$+so9Aocgsy068HEhWbi5Kg$PgNgX4shYkTGSWkkpD2U0whRnvz2ltcoPH4dwRG8kvg",
			wantErr: database.ErrIncompatableArgon2Version,
		},
		{
			name:    "incorrect v parameter",
			hash:    "$argon2id$c=19$t=1,m=65536,p=4$+so9Aocgsy068HEhWbi5Kg$PgNgX4shYkTGSWkkpD2U0whRnvz2ltcoPH4dwRG8kvg",
			wantErr: errors.New("input does not match format"),
		},
		{
			name:    "incorrect p parameter",
			hash:    "$argon2id$v=19$t=1,m=65536,s=4$+so9oAcgsy068HEhWbi5Kg$PgNgX4shYkTGSWkkpD2U0whRnvz2ltcoPH4dwRG8kvg",
			wantErr: nil,
		},
		{
			name:    "invalid base64 salt",
			hash:    "$argon2id$v=19$t=1,m=65536,p=4$+so9o.cgsy068HEhWbi5Kg$PgNgX4shYkTGSWkkpD2U0whRnvz2ltcoPH4dwRG8kvg",
			wantErr: errors.New("illegal base64 data at input byte 5"),
		},
		{
			name:    "invalid base64 key",
			hash:    "$argon2id$v=19$t=1,m=65536,p=4$+so9oAcgsy068HEhWbi5Kg$PgNgX.shYkTGSWkkpD2U0whRnvz2ltcoPH4dwRG8kvg",
			wantErr: errors.New("illegal base64 data at input byte 5"),
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				salt []byte = make([]byte, base64.RawStdEncoding.DecodedLen(len(tc.wantData.Salt)))
				key  []byte = make([]byte, base64.RawStdEncoding.DecodedLen(len(tc.wantData.Key)))
			)
			_, err := base64.RawStdEncoding.Decode(salt, tc.wantData.Salt)
			if err != nil {
				t.Fatal(err)
			}
			_, err = base64.RawStdEncoding.Decode(key, tc.wantData.Key)
			if err != nil {
				t.Fatal(err)
			}

			var result database.Argon2Params
			err = database.DecodeHash(tc.hash, &result)
			if !errors.Is(err, tc.wantErr) {
				if err != nil && tc.wantErr != nil && err.Error() != tc.wantErr.Error() {
					t.Fatalf("wanted '%v', got '%v' error", tc.wantErr, err)
				} else if err != nil {
					return
				}
			} else if err != nil {
				return
			}

			if result.Version != tc.wantData.Version {
				t.Errorf("wanted '%d', got '%d' version", tc.wantData.Version, result.Version)
			}
			if result.Time != tc.wantData.Time {
				t.Errorf("wanted '%d', got '%d' time", tc.wantData.Time, result.Time)
			}
			if result.Memory != tc.wantData.Memory {
				t.Errorf("wanted '%d', got '%d' memory", tc.wantData.Memory, result.Memory)
			}
			if result.Threads != tc.wantData.Threads {
				t.Errorf("wanted '%d', got '%d' threads", tc.wantData.Threads, result.Threads)
			}
			if !reflect.DeepEqual(result.Salt, salt) {
				t.Errorf("wanted '%s', got '%s' salt", salt, result.Salt)
			}
			if !reflect.DeepEqual(result.Key, key) {
				t.Errorf("wanted '%s', got '%s' key", key, result.Key)
			}
		})
	}
}

func TestVerifyHash(t *testing.T) {
	t.Parallel()

	secret := "very_secret_password123"
	hash, err := database.GenerateHash(secret)
	if err != nil {
		t.Fatal(err)
	}
	notSecret := "this_password_is_public"

	verified := database.VerifyHash(secret, hash)
	if !verified {
		t.Error("expected secret to be verified")
	}
	verified = database.VerifyHash(notSecret, hash)
	if verified {
		t.Error("expected notSecret to not be verified")
	}
}
