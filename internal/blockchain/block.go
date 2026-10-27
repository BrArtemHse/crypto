// Package blockchain implements the deliberately small blockchain experiment
// in practical work 5. It has no network or cryptocurrency functionality.
package blockchain

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"cryptolabs/internal/streebog"
)

type Transaction struct {
	Data      []byte
	Signature []byte
}

type Block struct {
	Version      int           `json:"version"`
	Public       string        `json:"public_key"`
	Header       string        `json:"header"`
	Hash         string        `json:"hash"`
	Transactions []Transaction `json:"-"`
}

func MerkleRoot(leaves [][32]byte) ([32]byte, error) {
	if len(leaves) == 0 {
		return [32]byte{}, errors.New("Merkle tree needs at least one leaf")
	}
	level := append([][32]byte(nil), leaves...)
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			j := i + 1
			if j == len(level) {
				j = i
			}
			var pair [64]byte
			copy(pair[:32], level[i][:])
			copy(pair[32:], level[j][:])
			next = append(next, streebog.Sum256(pair[:]))
		}
		level = next
	}
	return level[0], nil
}

func transactionRoot(txs []Transaction) ([32]byte, error) {
	leaves := make([][32]byte, len(txs))
	for i, tx := range txs {
		data := make([]byte, 0, len(tx.Data)+len(tx.Signature))
		data = append(data, tx.Data...)
		data = append(data, tx.Signature...)
		leaves[i] = streebog.Sum256(data)
	}
	return MerkleRoot(leaves)
}

func Generate(name string, at time.Time) (*Block, error) {
	rng, err := NewPRNG(name)
	if err != nil {
		return nil, err
	}
	if at.Year() < 2000 || at.Year() > 2099 {
		return nil, errors.New("timestamp year must be in 2000..2099")
	}
	if err = validateGroup(); err != nil {
		return nil, err
	}
	p, q, g := Parameters()
	x, err := randomScalar(rng, q)
	if err != nil {
		return nil, err
	}
	public := new(big.Int).Exp(g, x, p)
	block := &Block{Version: 1, Public: fmt.Sprintf("%0128x", public), Transactions: make([]Transaction, 5)}
	used := make(map[string]bool)
	for i := range block.Transactions {
		tx := &block.Transactions[i]
		tx.Data = make([]byte, 200)
		if _, err = io.ReadFull(rng, tx.Data); err != nil {
			return nil, err
		}
		if i == 0 {
			copy(tx.Data, []byte(name))
		}
		var nonce *big.Int
		for {
			nonce, err = randomScalar(rng, q)
			if err != nil {
				return nil, err
			}
			if !used[nonce.String()] {
				used[nonce.String()] = true
				break
			}
		}
		sig, err := SignWithNonce(tx.Data, x, nonce)
		if err != nil {
			return nil, err
		}
		tx.Signature = encodeSignature(sig)
	}
	root, err := transactionRoot(block.Transactions)
	if err != nil {
		return nil, err
	}
	var header [76]byte
	for i := 0; i < 4; i++ {
		for header[i] == 0 {
			if _, err = io.ReadFull(rng, header[i:i+1]); err != nil {
				return nil, err
			}
		}
	}
	if _, err = io.ReadFull(rng, header[4:36]); err != nil {
		return nil, err
	}
	copy(header[36:68], root[:])
	copy(header[68:72], []byte{byte(at.Hour()), byte(at.Day()), byte(at.Month()), byte(at.Year() % 100)})
	for nonce := uint64(0); nonce <= uint64(^uint32(0)); nonce++ {
		binary.BigEndian.PutUint32(header[72:], uint32(nonce))
		hash := streebog.Sum256(header[:])
		if hash[0]&0xf8 == 0 {
			block.Header = hex.EncodeToString(header[:])
			block.Hash = hex.EncodeToString(hash[:])
			return block, nil
		}
	}
	return nil, errors.New("uint32 nonce range exhausted")
}

func (b *Block) verify() error {
	if b.Version != 1 || len(b.Transactions) != 5 {
		return errors.New("unsupported version or transaction count")
	}
	if err := validateGroup(); err != nil {
		return err
	}
	publicBytes, err := fixedHex(b.Public, 64)
	if err != nil {
		return fmt.Errorf("public key: %w", err)
	}
	public := new(big.Int).SetBytes(publicBytes)
	seen := make(map[string]bool)
	for i, tx := range b.Transactions {
		if len(tx.Data) != 200 {
			return fmt.Errorf("transaction %d must be 200 bytes", i+1)
		}
		sig, err := decodeSignature(tx.Signature)
		if err != nil {
			return fmt.Errorf("signature %d: %w", i+1, err)
		}
		if !VerifySignature(tx.Data, public, sig) {
			return fmt.Errorf("signature %d is invalid", i+1)
		}
		if seen[sig.R.String()] {
			return errors.New("repeated Schnorr nonce")
		}
		seen[sig.R.String()] = true
	}
	header, err := fixedHex(b.Header, 76)
	if err != nil {
		return fmt.Errorf("header: %w", err)
	}
	for _, v := range header[:4] {
		if v == 0 {
			return errors.New("size field contains a zero byte")
		}
	}
	stamp := header[68:72]
	when := time.Date(2000+int(stamp[3]), time.Month(stamp[2]), int(stamp[1]), int(stamp[0]), 0, 0, 0, time.UTC)
	if stamp[3] > 99 || when.Year() != 2000+int(stamp[3]) || int(when.Month()) != int(stamp[2]) || when.Day() != int(stamp[1]) || when.Hour() != int(stamp[0]) {
		return errors.New("invalid timestamp bytes")
	}
	root, err := transactionRoot(b.Transactions)
	if err != nil {
		return err
	}
	if !bytes.Equal(header[36:68], root[:]) {
		return errors.New("Merkle root mismatch")
	}
	claimed, err := fixedHex(b.Hash, 32)
	if err != nil {
		return fmt.Errorf("block hash: %w", err)
	}
	actual := streebog.Sum256(header)
	if !bytes.Equal(actual[:], claimed) || actual[0]&0xf8 != 0 {
		return errors.New("block hash or proof of work mismatch")
	}
	return nil
}

func fixedHex(s string, size int) ([]byte, error) {
	if len(s) != size*2 {
		return nil, fmt.Errorf("expected %d hex characters", size*2)
	}
	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return data, nil
}
