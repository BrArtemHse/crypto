package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"cryptolabs/internal/streebog"
)

func run(args []string) error {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		fmt.Println("команды: hash -in ФАЙЛ [-out ХЭШ]; check -in ФАЙЛ -hash ХЭШ")
		return nil
	}
	if len(args) == 0 || (args[0] != "hash" && args[0] != "check") {
		return errors.New("команды: hash -in ФАЙЛ [-out ХЭШ]; check -in ФАЙЛ -hash ХЭШ")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	in := fs.String("in", "", "входной файл")
	out := fs.String("out", "", "файл хэша")
	saved := fs.String("hash", "", "сохранённый хэш")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *in == "" || fs.NArg() != 0 || (args[0] == "hash" && *saved != "") || (args[0] == "check" && (*saved == "" || *out != "")) {
		return errors.New("неверные аргументы")
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	digest := streebog.Sum256(data)
	if args[0] == "hash" {
		line := hex.EncodeToString(digest[:]) + "\n"
		if *out != "" {
			f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			_, writeErr := io.WriteString(f, line)
			closeErr := f.Close()
			if writeErr != nil {
				return writeErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
		fmt.Print(line)
		return nil
	}
	f, err := os.Open(*saved)
	if err != nil {
		return err
	}
	b, readErr := io.ReadAll(io.LimitReader(f, 1025))
	closeErr := f.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if len(b) > 1024 {
		return errors.New("слишком длинный файл хэша")
	}
	text := strings.TrimSpace(string(b))
	if len(text) != 64 {
		return errors.New("хэш должен содержать 64 hex-цифры")
	}
	expected, err := hex.DecodeString(text)
	if err != nil {
		return errors.New("неверный hex хэша")
	}
	if !bytes.Equal(digest[:], expected) {
		return errors.New("хэш не совпадает")
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
