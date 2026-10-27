package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"cryptolabs/internal/ec"
	"cryptolabs/internal/gostsign"
)

const algorithm = "gost3410-2012-256-rfc7091-test"

type privateKey struct {
	Algorithm string `json:"algorithm"`
	D         string `json:"d"`
}
type publicKey struct {
	Algorithm string `json:"algorithm"`
	X         string `json:"x"`
	Y         string `json:"y"`
}

func encodeNumber(n *big.Int) string { return hex.EncodeToString(n.FillBytes(make([]byte, 32))) }
func decodeNumber(s string) (*big.Int, error) {
	if len(s) != 64 {
		return nil, errors.New("число ключа должно содержать ровно 64 hex-цифры")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("файл превышает допустимый размер")
	}
	return b, nil
}
func readJSON(path string, dst any) error {
	b, err := readLimited(path, 4096)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("лишние данные после JSON ключа")
	}
	return nil
}
func writeNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(b)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}
func ensureAbsent(path string) error {
	_, err := os.Lstat(path)
	if err == nil {
		return fmt.Errorf("выходной файл уже существует: %s", path)
	}
	if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func run(args []string) error {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		fmt.Println("команды: keygen -private ФАЙЛ -public ФАЙЛ; sign -in ФАЙЛ -key КЛЮЧ -out ПОДПИСЬ; verify -in ФАЙЛ -key КЛЮЧ -sig ПОДПИСЬ")
		return nil
	}
	if len(args) == 0 || (args[0] != "keygen" && args[0] != "sign" && args[0] != "verify") {
		return errors.New("команды: keygen -private ФАЙЛ -public ФАЙЛ; sign -in ФАЙЛ -key КЛЮЧ -out ПОДПИСЬ; verify -in ФАЙЛ -key КЛЮЧ -sig ПОДПИСЬ")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	private, public, in, key, out, sigPath := "", "", "", "", "", ""
	switch args[0] {
	case "keygen":
		fs.StringVar(&private, "private", "", "секретный ключ")
		fs.StringVar(&public, "public", "", "открытый ключ")
	case "sign":
		fs.StringVar(&in, "in", "", "входной файл")
		fs.StringVar(&key, "key", "", "секретный ключ")
		fs.StringVar(&out, "out", "", "подпись")
	case "verify":
		fs.StringVar(&in, "in", "", "входной файл")
		fs.StringVar(&key, "key", "", "открытый ключ")
		fs.StringVar(&sigPath, "sig", "", "подпись")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("лишние аргументы")
	}
	scheme := gostsign.TestScheme()
	if args[0] == "keygen" {
		if private == "" || public == "" {
			return errors.New("требуются -private и -public")
		}
		a, err := filepath.Abs(private)
		if err != nil {
			return err
		}
		b, err := filepath.Abs(public)
		if err != nil {
			return err
		}
		if a == b {
			return errors.New("имена файлов ключей должны различаться")
		}
		if err := ensureAbsent(private); err != nil {
			return err
		}
		if err := ensureAbsent(public); err != nil {
			return err
		}
		d, p, err := scheme.GenerateKey()
		if err != nil {
			return err
		}
		secret, err := json.MarshalIndent(privateKey{algorithm, encodeNumber(d)}, "", "  ")
		if err != nil {
			return err
		}
		pub, err := json.MarshalIndent(publicKey{algorithm, encodeNumber(p.X), encodeNumber(p.Y)}, "", "  ")
		if err != nil {
			return err
		}
		if err := writeNew(private, append(secret, '\n')); err != nil {
			return err
		}
		if err := writeNew(public, append(pub, '\n')); err != nil {
			_ = os.Remove(private)
			return err
		}
		fmt.Println("Ключи созданы")
		return nil
	}
	if in == "" || key == "" || (args[0] == "sign" && out == "") || (args[0] == "verify" && sigPath == "") {
		return errors.New("не заданы обязательные параметры")
	}
	data, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	if args[0] == "sign" {
		if err := ensureAbsent(out); err != nil {
			return err
		}
		var stored privateKey
		if err := readJSON(key, &stored); err != nil {
			return err
		}
		if stored.Algorithm != algorithm {
			return errors.New("неверный алгоритм ключа")
		}
		d, err := decodeNumber(stored.D)
		if err != nil {
			return err
		}
		sig, err := scheme.Sign(data, d)
		if err != nil {
			return err
		}
		if err := writeNew(out, sig); err != nil {
			return err
		}
		fmt.Println("Подпись сохранена")
		return nil
	}
	var stored publicKey
	if err := readJSON(key, &stored); err != nil {
		return err
	}
	if stored.Algorithm != algorithm {
		return errors.New("неверный алгоритм ключа")
	}
	x, err := decodeNumber(stored.X)
	if err != nil {
		return err
	}
	y, err := decodeNumber(stored.Y)
	if err != nil {
		return err
	}
	p := ec.Point{X: x, Y: y}
	if err := scheme.ValidatePublic(p); err != nil {
		return err
	}
	sig, err := readLimited(sigPath, 64)
	if err != nil {
		return err
	}
	if !scheme.Verify(data, p, sig) {
		return errors.New("подпись недействительна")
	}
	fmt.Println("OK")
	return nil
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
	}
}
