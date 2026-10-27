package blockchain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Save creates a new directory; existing directories and files are never reused.
// A write failure can leave a partial directory, which verification will reject.
func (b *Block) Save(dir string) error {
	if b == nil {
		return errors.New("nil block")
	}
	if err := b.verify(); err != nil {
		return fmt.Errorf("refuse to save invalid block: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return fmt.Errorf("create new block directory: %w", err)
	}
	for i, tx := range b.Transactions {
		if err := writeNew(filepath.Join(dir, fmt.Sprintf("tx%02d.bin", i+1)), tx.Data); err != nil {
			return err
		}
		if err := writeNew(filepath.Join(dir, fmt.Sprintf("tx%02d.sig", i+1)), tx.Signature); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return writeNew(filepath.Join(dir, "block.json"), append(data, '\n'))
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", filepath.Base(path), limit)
	}
	return data, nil
}

func VerifyDirectory(dir string) error {
	data, err := readBounded(filepath.Join(dir, "block.json"), 16384)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var b Block
	if err = decoder.Decode(&b); err != nil {
		return fmt.Errorf("decode block.json: %w", err)
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing data in block.json")
	}
	b.Transactions = make([]Transaction, 5)
	for i := range b.Transactions {
		b.Transactions[i].Data, err = readBounded(filepath.Join(dir, fmt.Sprintf("tx%02d.bin", i+1)), 200)
		if err != nil {
			return err
		}
		b.Transactions[i].Signature, err = readBounded(filepath.Join(dir, fmt.Sprintf("tx%02d.sig", i+1)), 96)
		if err != nil {
			return err
		}
	}
	return b.verify()
}
