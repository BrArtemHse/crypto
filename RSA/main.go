package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"

	"cryptolabs/internal/rsalab"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
	}
}

func parseInteger(s string) (*big.Int, error) {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || len(s) > 2467 {
		return nil, errors.New("неверное десятичное число")
	}
	return n, nil
}

func run(args []string) error {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		fmt.Println("команды: keygen, encrypt, decrypt, number, attack; <команда> --help выводит флаги")
		return nil
	}
	if len(args) == 0 {
		return errors.New("команды: keygen, encrypt, decrypt, number, attack")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(os.Stdout)
	switch args[0] {
	case "keygen", "number":
		pText := flags.String("p", "", "простое p")
		qText := flags.String("q", "", "простое q")
		eText := flags.String("e", "65537", "показатель e для заданных p,q")
		bits := flags.Int("bits", 2048, "размер случайного модуля")
		pub := flags.String("public", "", "новый JSON открытого ключа")
		priv := flags.String("private", "", "новый JSON закрытого ключа")
		message := flags.String("message", "", "десятичное сообщение для number")
		if err := flags.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("лишние аргументы")
		}
		if args[0] == "keygen" && (*pub == "" || *priv == "") {
			return errors.New("требуются --public и --private")
		}
		var k *rsalab.PrivateKey
		var err error
		if *pText != "" || *qText != "" {
			p, pErr := parseInteger(*pText)
			q, qErr := parseInteger(*qText)
			e, eErr := parseInteger(*eText)
			if pErr != nil || qErr != nil || eErr != nil {
				return errors.New("требуются корректные --p, --q, --e")
			}
			k, err = rsalab.FromPrimes(p, q, e)
		} else {
			if args[0] == "number" {
				return errors.New("number требует --p, --q, --e и --message")
			}
			if *eText != "65537" {
				return errors.New("для случайных ключей используется e=65537")
			}
			k, err = rsalab.Generate(*bits)
		}
		if err != nil {
			return err
		}
		if args[0] == "number" {
			m, err := parseInteger(*message)
			if err != nil {
				return err
			}
			c, err := rsalab.EncryptNumber(&k.PublicKey, m)
			if err != nil {
				return err
			}
			restored, err := rsalab.DecryptNumber(k, c)
			if err != nil {
				return err
			}
			phi := new(big.Int).Mul(new(big.Int).Sub(k.P, big.NewInt(1)), new(big.Int).Sub(k.Q, big.NewInt(1)))
			fmt.Printf("n=%s phi=%s e=%s d=%s m=%s c=%s restored=%s\n", k.N, phi, k.E, k.D, m, c, restored)
			return nil
		}
		publicData, err := rsalab.MarshalPublic(&k.PublicKey)
		if err != nil {
			return err
		}
		privateData, err := rsalab.MarshalPrivate(k)
		if err != nil {
			return err
		}
		if err := writePair(*pub, publicData, *priv, privateData); err != nil {
			return err
		}
		fmt.Printf("Созданы ключи RSA, модуль %d бит\n", k.N.BitLen())
		return nil
	case "encrypt", "decrypt":
		keyPath := flags.String("key", "", "JSON ключа")
		input := flags.String("in", "", "входной файл")
		output := flags.String("out", "", "новый выходной файл")
		if err := flags.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if flags.NArg() != 0 || *keyPath == "" || *input == "" || *output == "" {
			return errors.New("требуются --key, --in и --out")
		}
		keyData, err := readKey(*keyPath)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(*input)
		if err != nil {
			return err
		}
		var result []byte
		if args[0] == "encrypt" {
			k, parseErr := rsalab.ParsePublic(keyData)
			if parseErr != nil {
				return parseErr
			}
			result, err = rsalab.Encrypt(k, data)
		} else {
			k, parseErr := rsalab.ParsePrivate(keyData)
			if parseErr != nil {
				return parseErr
			}
			result, err = rsalab.Decrypt(k, data)
		}
		if err != nil {
			return err
		}
		if err := writeNew(*output, result); err != nil {
			return err
		}
		fmt.Printf("Сохранено %d байт: %s\n", len(result), *output)
		return nil
	case "attack":
		keyPath := flags.String("key", "", "JSON открытого ключа")
		iterations := flags.Uint64("iterations", 100000, "предел кандидатов Ферма, 1…10000000")
		output := flags.String("out", "", "новый JSON восстановленного закрытого ключа")
		if err := flags.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if flags.NArg() != 0 || *keyPath == "" || *output == "" {
			return errors.New("требуются --key и --out")
		}
		data, err := readKey(*keyPath)
		if err != nil {
			return err
		}
		public, err := rsalab.ParsePublic(data)
		if err != nil {
			return err
		}
		k, steps, err := rsalab.Fermat(public.N, public.E, *iterations)
		if err != nil {
			return err
		}
		data, err = rsalab.MarshalPrivate(k)
		if err != nil {
			return err
		}
		if err := writeNew(*output, data); err != nil {
			return err
		}
		fmt.Printf("p=%s q=%s d=%s; проверено кандидатов: %d\n", k.P, k.Q, k.D, steps)
		return nil
	default:
		return errors.New("неизвестная команда; доступны keygen, encrypt, decrypt, number, attack")
	}
}

func readKey(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return nil, err
	}
	if len(data) > 65536 {
		return nil, errors.New("JSON ключа превышает 64 КиБ")
	}
	return data, nil
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

func writePair(publicPath string, publicData []byte, privatePath string, privateData []byte) error {
	first, err := os.OpenFile(publicPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	second, err := os.OpenFile(privatePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		_ = first.Close()
		_ = os.Remove(publicPath)
		return err
	}
	_, err = first.Write(publicData)
	if err == nil {
		_, err = second.Write(privateData)
	}
	firstClose, secondClose := first.Close(), second.Close()
	if err == nil {
		err = firstClose
	}
	if err == nil {
		err = secondClose
	}
	if err != nil {
		_ = os.Remove(publicPath)
		_ = os.Remove(privatePath)
	}
	return err
}
