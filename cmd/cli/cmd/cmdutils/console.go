package cmdutils

import (
	"fmt"
	"strings"
)

// Labels2String converts the labels map to a single console string
func Labels2String(m map[string]string) string {
	s := ""
	for k, v := range m {
		if s != "" {
			s = s + ", "
		}
		s = fmt.Sprintf("%s%s:%s", s, k, v)
	}
	return s
}

// Slice2String converts the labels map to a single console string
func Slice2String(ls []string) string {
	s := ""
	for _, v := range ls {
		if s != "" {
			s = s + ", "
		}
		s = fmt.Sprintf("%s%s", s, v)
	}
	return s
}

// Slice2Map converts a slice of strings dedicated to usage as labels, into a label map
func Slice2Map(ls []string) map[string]string {
	m := make(map[string]string)
	for _, l := range ls {
		ss := strings.SplitN(l, ":", 2)
		if len(ss) == 2 {
			lng := ss[0]
			lbl := ss[1]
			m[lng] = lbl
		}
	}
	return m
}
