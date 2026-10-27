package rsalab

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/big"
)

type publicJSON struct {
	Version int    `json:"version"`
	N       string `json:"n"`
	E       string `json:"e"`
}
type privateJSON struct {
	Version int    `json:"version"`
	N       string `json:"n"`
	E       string `json:"e"`
	D       string `json:"d"`
	P       string `json:"p"`
	Q       string `json:"q"`
}

func decodeJSON(data []byte, value any) error {
	if len(data) > 65536 {
		return errors.New("слишком большой JSON ключа")
	}
	// encoding/json otherwise silently accepts repeated object fields.
	scanner := json.NewDecoder(bytes.NewReader(data))
	start, err := scanner.Token()
	if err != nil || start != json.Delim('{') {
		return errors.New("ключ должен быть JSON-объектом")
	}
	seen := make(map[string]bool)
	for scanner.More() {
		token, err := scanner.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			return errors.New("повторяющееся поле JSON ключа")
		}
		seen[name] = true
		var raw json.RawMessage
		if err := scanner.Decode(&raw); err != nil {
			return err
		}
	}
	if _, err := scanner.Token(); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("лишние данные после JSON ключа")
	}
	return nil
}

func decimal(s string) (*big.Int, error) {
	if len(s) == 0 || len(s) > 2467 || s[0] == '0' {
		return nil, errors.New("ожидалась положительная десятичная строка")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return nil, errors.New("неверная десятичная строка")
		}
	}
	x, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, errors.New("неверное число")
	}
	return x, nil
}

func MarshalPublic(k *PublicKey) ([]byte, error) {
	if err := validatePublic(k); err != nil {
		return nil, err
	}
	return json.MarshalIndent(publicJSON{1, k.N.String(), k.E.String()}, "", "  ")
}

func MarshalPrivate(k *PrivateKey) ([]byte, error) {
	if err := validatePrivate(k); err != nil {
		return nil, err
	}
	return json.MarshalIndent(privateJSON{1, k.N.String(), k.E.String(), k.D.String(), k.P.String(), k.Q.String()}, "", "  ")
}

func ParsePublic(data []byte) (*PublicKey, error) {
	var wire publicJSON
	if err := decodeJSON(data, &wire); err != nil {
		return nil, err
	}
	if wire.Version != 1 {
		return nil, errors.New("неподдерживаемая версия ключа")
	}
	n, err := decimal(wire.N)
	if err != nil {
		return nil, err
	}
	e, err := decimal(wire.E)
	if err != nil {
		return nil, err
	}
	k := &PublicKey{n, e}
	return k, validatePublic(k)
}

func ParsePrivate(data []byte) (*PrivateKey, error) {
	var wire privateJSON
	if err := decodeJSON(data, &wire); err != nil {
		return nil, err
	}
	if wire.Version != 1 {
		return nil, errors.New("неподдерживаемая версия ключа")
	}
	var values [5]*big.Int
	for i, s := range []string{wire.N, wire.E, wire.D, wire.P, wire.Q} {
		x, err := decimal(s)
		if err != nil {
			return nil, err
		}
		values[i] = x
	}
	k := &PrivateKey{PublicKey{values[0], values[1]}, values[2], values[3], values[4]}
	return k, validatePrivate(k)
}
