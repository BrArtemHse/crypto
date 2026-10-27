package main

import (
	"cryptolabs/internal/ec"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
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
func number(s string) (*big.Int, error) {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("неверное целое число %q", s)
	}
	if v.BitLen() > 4096 {
		return nil, errors.New("число превышает учебный предел 4096 бит")
	}
	return v, nil
}
func point(s string, c *ec.Curve) (ec.Point, error) {
	if s == "inf" {
		return ec.Point{Inf: true}, nil
	}
	parts := strings.Split(s, ",")
	if len(parts) != 2 {
		return ec.Point{}, errors.New("точка задаётся как x,y или inf")
	}
	x, err := number(parts[0])
	if err != nil {
		return ec.Point{}, err
	}
	y, err := number(parts[1])
	if err != nil {
		return ec.Point{}, err
	}
	p := ec.Point{X: x, Y: y}
	if !c.OnCurve(p) {
		return ec.Point{}, errors.New("точка не принадлежит кривой или координаты вне [0,p)")
	}
	return p, nil
}
func format(p ec.Point) string {
	if p.Inf {
		return "O"
	}
	return "(" + p.X.String() + "," + p.Y.String() + ")"
}
func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("команда: info | add | mul | subgroups; --help после команды")
	}
	command := args[0]
	switch command {
	case "info", "add", "mul", "subgroups":
	default:
		return fmt.Errorf("неизвестная команда %q", command)
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(out)
	ps := fs.String("p", "1031", "простое p>3")
	as := fs.String("a", "1", "коэффициент a")
	bs := fs.String("b", "0", "коэффициент b")
	first := fs.String("point", "inf", "точка x,y или inf")
	second := fs.String("other", "inf", "вторая точка x,y или inf")
	scalar := fs.String("k", "1", "целый скаляр")
	limit := fs.Int("limit", 10, "предел вывода точек")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("неожиданные позиционные аргументы")
	}
	if *limit < 0 || *limit > 16384 {
		return errors.New("limit должен быть в [0,16384]")
	}
	p, err := number(*ps)
	if err != nil {
		return err
	}
	a, err := number(*as)
	if err != nil {
		return err
	}
	b, err := number(*bs)
	if err != nil {
		return err
	}
	c, err := ec.New(p, a, b)
	if err != nil {
		return err
	}
	switch command {
	case "info":
		points, e := c.Points()
		if e != nil {
			return e
		}
		fmt.Fprintf(out, "p=%s a=%s b=%s\nПорядок группы: %d\n", c.P, c.A, c.B, len(points))
		for _, v := range points[:min(*limit, len(points))] {
			fmt.Fprintln(out, format(v))
		}
	case "subgroups":
		groups, e := c.PrimeSubgroups()
		if e != nil {
			return e
		}
		fmt.Fprintf(out, "Подгрупп простого порядка: %d\n", len(groups))
		for _, g := range groups {
			fmt.Fprintf(out, "Порядок: %d; образующая: %s\n", g.Order, format(g.Generator))
			for _, v := range g.Points[:min(*limit, len(g.Points))] {
				fmt.Fprintln(out, format(v))
			}
		}
	case "add", "mul":
		v, e := point(*first, c)
		if e != nil {
			return e
		}
		var result ec.Point
		if command == "add" {
			w, e := point(*second, c)
			if e != nil {
				return e
			}
			result = c.Add(v, w)
		} else {
			k, e := number(*scalar)
			if e != nil {
				return e
			}
			result = c.Mul(v, k)
		}
		fmt.Fprintln(out, format(result))
	}
	return nil
}
