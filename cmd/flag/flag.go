package flag

import (
	"flag"

	"github.com/peterbourgon/ff/v4"
)

type FlagConfig struct {
	Name     string
	Usage    string
	disabled bool
}

type FlagSet struct {
	*ff.FlagSet
}

// FlagConfigSet allows for helper methods on FlagConfig's to be created.
type FlagConfigSet map[string]*FlagConfig

func (f *FlagConfig) Disable() {
	f.disabled = true
}

func (f *FlagConfig) Enable() {
	f.disabled = false
}

func (fs *FlagSet) Register(f FlagConfig, fv flag.Value) {
	if !f.disabled {
		fs.AddFlag(ff.FlagConfig{
			LongName: f.Name,
			Usage:    f.Usage,
			Value:    fv,
		})
	}
}

// Disable will disable a flag by name.
func (s FlagConfigSet) Disable(name string) {
	if f, ok := s[name]; ok {
		f.Disable()
	}
}

// Get will return the FlagConfig by given name.
func (s FlagConfigSet) Get(name string) FlagConfig {
	if f, ok := s[name]; ok {
		return *f
	}
	return FlagConfig{}
}

func Register(fs *ff.FlagSet, f *ff.FlagConfig, fv flag.Value) {
	fs.AddFlag(ff.FlagConfig{
		LongName: f.LongName,
		Usage:    f.Usage,
		Value:    fv,
	})
}

func zeroVal[T any](v *T) T {
	if v != nil {
		return *v
	}
	return *new(T) // zero value of T
}

func toPtr[T any](v T) *T {
	return &v
}
