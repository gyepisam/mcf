package scrypt

import (
	"testing"
)

var password = []byte("yssIi0AL")
var salt = []byte("d8sYrQbgT")

var mcf = "$scrypt$14,8,1$643873597251626754$e6b2da790d99bef794d6feb8ab7fda61f44251303da936ad75162454fe3017e80302ed0fdf654ade552906819aee1370278e852aa2ee9ca9b91e934c6337d6607c94a98e6c06b7279cbfc30d9c783d30e9958ae601dd90d57dcc162eebc513164bd717abe23e7b8281cc13865e0d7453ccd36ff9dbfcb7aadf2451da926c8413"

func TestRoundtrip(t *testing.T) {
	s := &Config{
		Name:    "scrypt",
		HashLen: 128,
		LogN:    14,
		R:       8,
		P:       1,
	}

	p, err := s.Generate(password, salt)
	if err != nil {
		t.Fatal(err)
	}
	
//	t.Logf("Salt: %s", p.Salt)
//	t.Logf("Digest: %x", p.Digest)
	
	m, err := p.String()
	if err != nil {
		t.Fatal(err)
	}

	if m != mcf {
		t.Fatalf("generated mcf\n%s\ndoes not match expected\n%s\n", m, mcf)
	}

	valid, err := s.Verify(string(password), p)
	if err != nil {
		t.Fatal(err)
	}

	if !valid {
		t.Fatalf("Generated value does not verify!")
	}
}
