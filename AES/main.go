package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"

	"cryptolabs/internal/aes128"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		fmt.Println("команды: encrypt|decrypt --key HEX32 --in ФАЙЛ --out НОВЫЙ_ФАЙЛ")
		return nil
	}
	if len(args) == 0 || (args[0] != "encrypt" && args[0] != "decrypt") {
		return errors.New("команды: encrypt|decrypt --key HEX32 --in ФАЙЛ --out НОВЫЙ_ФАЙЛ")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(os.Stdout)
	keyHex := flags.String("key", "", "128-битный ключ в hex")
	input := flags.String("in", "", "входной файл")
	output := flags.String("out", "", "новый выходной файл")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || *input == "" || *output == "" {
		return errors.New("требуются --key, --in и --out; позиционные аргументы не поддерживаются")
	}
	key, err := hex.DecodeString(*keyHex)
	if err != nil || len(key) != 16 {
		return errors.New("--key должен содержать ровно 32 hex-символа")
	}
	data, err := os.ReadFile(*input)
	if err != nil {
		return err
	}
	var result []byte
	if args[0] == "encrypt" {
		result, err = aes128.EncryptCBC(key, data, rand.Reader)
	} else {
		result, err = aes128.DecryptCBC(key, data)
	}
	if err != nil {
		return err
	}
	if err := writeNew(*output, result); err != nil {
		return err
	}
	fmt.Printf("Сохранено %d байт: %s\n", len(result), *output)
	return nil
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}
