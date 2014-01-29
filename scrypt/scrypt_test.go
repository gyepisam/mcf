package scrypt

import (
	"github.com/gyepisam/mcf"

	"testing"
)

var testData = []struct { plaintext string; passwd string } {
{"yssIi0AL",
"$scrypt$KeyLen=128,LgN=16,R=10,P=2$PmxwHoNHjIILwrdOG8vA+A==$KRYMgbJr4vrYutrEjtueDDylXHQ2EoePyPoqtrDnil0jm1RfuyxT90/3gce5hw0/DTVmpcDnzkt1MWiK+zfS7+hh1EONspTZl8nGFLCsXcGiarrNKSSyRnsJN0DmSe20cfxodAB+DN1f84hxZbdmF20A2uFj36kE2ZKgTdlAYFE="},
{"yssIi0AL", "$scrypt$KeyLen=128,LgN=14,R=8,P=1$643873597251626754$e6b2da790d99bef794d6feb8ab7fda61f44251303da936ad75162454fe3017e80302ed0fdf654ade552906819aee1370278e852aa2ee9ca9b91e934c6337d6607c94a98e6c06b7279cbfc30d9c783d30e9958ae601dd90d57dcc162eebc513164bd717abe23e7b8281cc13865e0d7453ccd36ff9dbfcb7aadf2451da926c8413"},

var plaintext = "g5Dr58dvyD"
var salt = []byte("d8sYrQbgT")

func roundTrip(t *testing.T, plaintext string) {
	passwd, err := mcf.Generate(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := mcf.Verify(plaintext, passwd)
	if err != nil {
		t.Fatal(err)
	}

	if !ok {
		t.Fatalf("Verify(%q, %q) failed", plaintext, passwd)
	} else {
       t.Logf("{%q, %q},\n", plaintext, passwd)
    }
}

func TestVerificationExisting(t *testing.T) {
  for _, slot := range testData {
	valid, err := mcf.Verify(slot.plaintext, slot.passwd)
	if err != nil {
		panic(err)
	}
	if !valid {
		t.Fatalf("#1 Verify(%q, %q) failed", slot.plaintext, slot.passwd)
	}
  }
}

func TestRoundtrip(t *testing.T) {
	roundTrip(t, )
}

func TestCustomParameters(t *testing.T) {

	defaultConf := GetConfig()
	conf := defaultConf

	conf.KeyLen = 128
	conf.LgN = 14
	conf.R = 8
	conf.P = 1

    defaultParams := (&defaultConf).Params()
    newParams := (&conf).Params()

	if defaultParams == newParams {
		t.Fatalf("Expected different params, not: %s", newParams)
	}

	err := SetConfig(conf)
	if err != nil {
		panic(err)
	}

	roundTrip(t, plaintext)
}
