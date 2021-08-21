package b

import (
	"crypto/md5"
	"fmt"
)

//go:noinline
func Used(s string) string {
	if hash(s) == "d41d8cd98f00b204e9800998ecf8427e" {
		return ""
	}
	return s
}

func hash(s interface{}) string {
	h := md5.New()
	fmt.Fprint(h, s)
	return fmt.Sprintf("%x", h.Sum(nil))
}

//go:noinline
func Unused(s string) string { return s }
