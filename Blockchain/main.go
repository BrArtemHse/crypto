package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"cryptolabs/internal/blockchain"
)

func run(args []string, out io.Writer) error {
	usage := "Usage: Blockchain generate --name 'Фамилия Имя' --out results/block [--time RFC3339]\n       Blockchain verify --dir results/block"
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(out, usage)
		return nil
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(out)
	switch args[0] {
	case "generate":
		name := fs.String("name", "", "Фамилия и имя, 1..64 байта UTF-8")
		dir := fs.String("out", "results/block", "Новая выходная папка")
		stamp := fs.String("time", "", "Время RFC3339, иначе текущее локальное")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected positional arguments")
		}
		at := time.Now()
		var err error
		if *stamp != "" {
			at, err = time.Parse(time.RFC3339, *stamp)
			if err != nil {
				return fmt.Errorf("time: %w", err)
			}
		}
		b, err := blockchain.Generate(*name, at)
		if err != nil {
			return err
		}
		if err = b.Save(*dir); err != nil {
			return err
		}
		header, _ := hex.DecodeString(b.Header)
		fmt.Fprintf(out, "Created 5 signed transactions in %s\nMerkle root: %x\nNonce: %d\nBlock hash: %s\n", *dir, header[36:68], binary.BigEndian.Uint32(header[72:]), b.Hash)
		return nil
	case "verify":
		dir := fs.String("dir", "results/block", "Папка блока")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected positional arguments")
		}
		if err := blockchain.VerifyDirectory(*dir); err != nil {
			return err
		}
		fmt.Fprintln(out, "OK")
		return nil
	default:
		return fmt.Errorf("unknown command %q\n%s", args[0], usage)
	}
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
