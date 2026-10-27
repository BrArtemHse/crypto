package rsalab

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
)

const containerMagic = "RSALAB01"

func blockSizes(n *big.Int) (int, int, error) {
	plain, cipher := (n.BitLen()-1)/8, (n.BitLen()+7)/8
	if plain < 1 {
		return 0, 0, errors.New("для файлов RSA требуется n≥256")
	}
	return plain, cipher, nil
}

func Encrypt(k *PublicKey, data []byte) ([]byte, error) {
	if err := validatePublic(k); err != nil {
		return nil, err
	}
	b, c, err := blockSizes(k.N)
	if err != nil {
		return nil, err
	}
	count := len(data) / b
	if len(data)%b != 0 {
		count++
	}
	if count > (int(^uint(0)>>1)-20)/c {
		return nil, errors.New("слишком большой файл")
	}
	out := make([]byte, 20+count*c)
	copy(out, containerMagic)
	binary.BigEndian.PutUint32(out[8:12], uint32(c))
	binary.BigEndian.PutUint64(out[12:20], uint64(len(data)))
	for i, offset := 0, 20; i < len(data); offset += c {
		end := i + b
		if end > len(data) {
			end = len(data)
		}
		m := new(big.Int).SetBytes(data[i:end])
		encrypted := new(big.Int).Exp(m, k.E, k.N)
		encrypted.FillBytes(out[offset : offset+c])
		i = end
	}
	return out, nil
}

func Decrypt(k *PrivateKey, container []byte) ([]byte, error) {
	if err := validatePrivate(k); err != nil {
		return nil, err
	}
	b, c, err := blockSizes(k.N)
	if err != nil {
		return nil, err
	}
	if len(container) < 20 || !bytes.Equal(container[:8], []byte(containerMagic)) || binary.BigEndian.Uint32(container[8:12]) != uint32(c) || (len(container)-20)%c != 0 {
		return nil, errors.New("неверный заголовок или длина контейнера RSA")
	}
	length := binary.BigEndian.Uint64(container[12:20])
	blocks := length / uint64(b)
	if length%uint64(b) != 0 {
		blocks++
	}
	if blocks != uint64((len(container)-20)/c) || length > uint64(int(^uint(0)>>1)) {
		return nil, errors.New("исходная длина не соответствует контейнеру")
	}
	out := make([]byte, int(length))
	for offset, pos := 20, 0; offset < len(container); offset += c {
		encrypted := new(big.Int).SetBytes(container[offset : offset+c])
		if encrypted.Cmp(k.N) >= 0 {
			return nil, errors.New("шифроблок RSA не меньше n")
		}
		m := new(big.Int).Exp(encrypted, k.D, k.N)
		size := b
		if size > len(out)-pos {
			size = len(out) - pos
		}
		if len(m.Bytes()) > size {
			return nil, errors.New("открытый блок не помещается в исходную длину")
		}
		m.FillBytes(out[pos : pos+size])
		pos += size
	}
	return out, nil
}
