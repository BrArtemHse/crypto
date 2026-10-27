package main

import (
	"cryptolabs/internal/galois"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
	}
}
func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("команда: field | add | mul | inv | generators | powers | encrypt | decrypt; --help после команды")
	}
	command := args[0]
	switch command {
	case "field", "add", "mul", "inv", "generators", "powers", "encrypt", "decrypt":
	default:
		return fmt.Errorf("неизвестная команда %q", command)
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(out)
	p := fs.Int("p", 2, "простая характеристика")
	n := fs.Int("n", 8, "степень расширения")
	poly := fs.String("poly", "", "коэффициенты f от младшего, через запятую; пусто = поиск")
	x := fs.Int("x", 0, "индекс элемента x")
	y := fs.Int("y", 0, "индекс элемента y")
	alpha := fs.Int("alpha", 1, "ненулевой множитель")
	beta := fs.Int("beta", 0, "слагаемое")
	limit := fs.Int("limit", 32, "предел вывода элементов")
	input := fs.String("in", "", "входной файл")
	text := fs.String("text", "", "входная строка UTF-8 или JSON")
	output := fs.String("out", "", "новый выходной файл")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("неожиданные позиционные аргументы")
	}
	if *limit < 0 || *limit > galois.MaxOrder {
		return errors.New("limit должен быть в [0,65536]")
	}
	var modulus []int
	if *poly != "" {
		for _, s := range strings.Split(*poly, ",") {
			v, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil {
				return fmt.Errorf("коэффициент %q: %w", s, err)
			}
			modulus = append(modulus, v)
		}
	}
	f, err := galois.New(*p, *n, modulus)
	if err != nil {
		return err
	}
	valid := func(v int) error {
		if v < 0 || v >= f.Q {
			return fmt.Errorf("индекс %d должен быть в [0,%d)", v, f.Q)
		}
		return nil
	}
	switch command {
	case "field":
		fmt.Fprintf(out, "GF(%d^%d), q=%d, modulus=%v\n", f.P, f.N, f.Q, f.Modulus)
		count := min(*limit, f.Q)
		for i := 0; i < count; i++ {
			fmt.Fprintf(out, "%d\n", i)
		}
	case "add", "mul":
		if err = valid(*x); err != nil {
			return err
		}
		if err = valid(*y); err != nil {
			return err
		}
		v := f.Add(*x, *y)
		if command == "mul" {
			v = f.Mul(*x, *y)
		}
		fmt.Fprintln(out, v)
	case "inv":
		v, e := f.Inv(*x)
		if e != nil {
			return e
		}
		fmt.Fprintln(out, v)
	case "generators":
		values := f.Generators()
		fmt.Fprintf(out, "Образующих: %d\n", len(values))
		for _, v := range values[:min(*limit, len(values))] {
			fmt.Fprintln(out, v)
		}
	case "powers":
		if !f.IsGenerator(*x) {
			return errors.New("x не является образующей")
		}
		values := f.Powers(*x)
		for i, v := range values[:min(*limit, len(values))] {
			fmt.Fprintf(out, "%d^%d = %d\n", *x, i, v)
		}
	case "encrypt", "decrypt":
		hasText, hasInput := false, false
		fs.Visit(func(v *flag.Flag) {
			if v.Name == "text" {
				hasText = true
			}
			if v.Name == "in" {
				hasInput = true
			}
		})
		if hasText && hasInput {
			return errors.New("укажите только один из --text и --in")
		}
		data := []byte(*text)
		if hasInput {
			if *input == "" {
				return errors.New("пустое имя входного файла")
			}
			data, err = readInput(*input)
			if err != nil {
				return err
			}
		}
		if command == "encrypt" {
			data, err = f.Encrypt(data, *alpha, *beta)
		} else {
			data, err = f.Decrypt(data, *alpha, *beta)
		}
		if err != nil {
			return err
		}
		if *output != "" {
			return writeNew(*output, data)
		}
		_, err = out.Write(data)
		return err
	}
	return nil
}
func readInput(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (20<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 20<<20 {
		return nil, errors.New("вход превышает 20 МиБ")
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
	if err != nil {
		return err
	}
	return closeErr
}
