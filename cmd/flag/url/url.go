package url

import (
	"fmt"
	"net/url"
)

type URL struct{ *url.URL }

func (u *URL) String() string {
	if u.URL == nil {
		return ""
	}
	return u.URL.String()
}

func (u *URL) Set(s string) error {
	if s == "" {
		return nil
	}
	ur, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %q", s)
	}
	*u.URL = *ur

	return nil
}

func (u *URL) Type() string {
	return "url"
}
