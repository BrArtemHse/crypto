package streebog

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// RFC 6986 10.1.2/10.2.2 in the usual byte-stream order; additional
// boundary values: Botan src/tests/data/hash/streebog.vec (independent).
func TestSum256Vectors(t *testing.T) {
	vectors := []struct{ in, want string }{
		{"303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132", "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500"},
		{"d1e520e2e5f2f0e82c20d1f2f0e8e1eee6e820e2edf3f6e82c20e2e5fef2fa20f120eceef0ff20f1f2f0e5ebe0ece820ede020f5f0e0e1f0fbff20efebfaeafb20c8e3eef0e5e2fb", "9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50"},
		{"", "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb"},
		{"c6", "d907b672d09f48d27ad06c26647921c9e25d063c038eaaefac81e749dc1d98b5"},
		{"00b7d1c42da82cc055affead5924db662e5a080081697f8287c687fe91d32b4254fbb961725559a32c43c3f8114e05c2991108228ed83edc476fb9a62874fab1", "68367c34ad8441a48ac7fc65657ac73aa51e1a36c5346c0bf011945bcb9ef773"},
		{"89e8a4ccd6285add12b0c46506e91c09a3c2dd30951eb72818b58187f1a608edebf569fa81254970ad7f04ae9a25827fa6482829fdc0797a5cff6f7446d14576d2", "64f56da108ea18571aacb6852b5be57999ec5de82a7d1f719fcddfc7ec1b0ad1"},
		{"c1c065c63b1b848430326ded0cd23cffc644296813df0f968275492026737fd8d26f8690f19512e5a7c936050fc6b011d0538a6d5c1e75f839af3b0237d4a1accb497de6733f9717326260401a77a564e7bca93ae9fe7d257060e44ea08c350c9f64a78ce095fe29a7d1fc23de9350a47b71eda31514d134d84b5180930e29", "1ef768f7ae820c2966b7c60b0cf208ab89c1f7b60f9b2cab61253c38d1f2c987"},
		{"290f597702e009d86f49d5362346309e26919eacbcb86165be4906056d43f95a1e181b2b0c12785c929f17a3d25943f5313641c915bf5dd38882d587da1da65d6658f89764e28ee13a24ac9349e6803579baa17d6ca571793c13f7a0fe46043deeed08922fb2e2353d8718c5f1c7f1fba2df54e9cbbad54a750da656863d2843", "c9c82e740ccc34fc0c14c61ab4eb037542d77ffda00d484aff97c1144346704f"},
	}
	for _, v := range vectors {
		b, err := hex.DecodeString(v.in)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(fmt.Sprint(len(b)), func(t *testing.T) {
			got := Sum256(b)
			if hex.EncodeToString(got[:]) != v.want {
				t.Fatalf("got %x want %s", got, v.want)
			}
		})
	}
}

func TestDoesNotChangeInput(t *testing.T) {
	b := []byte("\x00\xffТочные байты файла")
	before := string(b)
	first := Sum256(b)
	second := Sum256(b)
	if string(b) != before || first != second {
		t.Fatal("input mutation or unstable digest")
	}
}

func TestPublishedInitialLPS(t *testing.T) {
	// RFC 6986 section 10.1: LPS(0^512) and LPS((00000001)^64).
	for _, v := range []struct {
		fill byte
		want string
	}{{0, "b383fc2eced4a574"}, {1, "23c5ee40b07b5f15"}} {
		var b [64]byte
		for i := range b {
			b[i] = v.fill
		}
		got := lps(b)
		for off := 0; off < 64; off += 8 {
			if hex.EncodeToString(got[off:off+8]) != v.want {
				t.Fatalf("LPS(%d) = %x", v.fill, got)
			}
		}
	}
}
