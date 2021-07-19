package main

import (
	"strings"
)

type stringSliceFlags []string

func (s *stringSliceFlags) String() string {
	return strings.Join([]string(*s), ", ")
}

func (s *stringSliceFlags) Set(value string) error {
	*s = append(*s, value)
	return nil
}
