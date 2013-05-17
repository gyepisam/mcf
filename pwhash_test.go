package pwhash 

import (
   "testing"
   "strings"
)

func TestRoundTrip(t *testing.T) {
  s := []string{"", "scrypt", "14,8,1", "643873597251626754", "e6b2da790d99bef794d6feb8ab7fda61f44251303da936ad75162454fe3017e80302ed0fdf654ade552906819aee1370278e852aa2ee9ca9b91e934c6337d6607c94a98e6c06b7279cbfc30d9c783d30e9958ae601dd90d57dcc162eebc513164bd717abe23e7b8281cc13865e0d7453ccd36ff9dbfcb7aadf2451da926c8413"}

  r := &Hash{Name: s[1], Options: s[2], Salt: []byte(s[3]), Digest: []byte(s[4])}

  str := strings.Join(s, Separator)

  h, err := Parse(str)
  if err != nil {
    t.Fatalf("Parse(%s) failed with error: %v!", str, err)
  }

  if r.Name != h.Name && r.Options != h.Options {
    t.Fatalf("h is %q, not %q", h , r)
  }

  q, err := h.String()
  if err != nil {
    t.Fatalf("Join(%v) failed with error: %v", h, err)
  }

  if q != str {
    t.Fatalf("[%v] is not [%v]", q, str)
  }
}
