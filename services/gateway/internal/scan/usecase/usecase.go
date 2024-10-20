package usecase

import (
	"errors"
	"net"
	"net/url"
	"regexp"
)

type Usecase struct {
}

func New() *Usecase {
	return &Usecase{}
}

func (uc *Usecase) DetermineInputType(input string) (string, error) {
	// Проверяем, является ли входная строка IP-адресом
	if net.ParseIP(input) != nil {
		return "ip", nil
	}

	// Проверяем, является ли входная строка URL
	u, err := url.Parse(input)
	if err == nil && u.Scheme != "" && u.Host != "" {
		return "url", nil
	}

	// Проверяем, является ли входная строка доменным именем
	if isValidDomain(input) {
		return "domain", nil
	}

	return "", errors.New("invalid input")
}

func isValidDomain(domain string) bool {
	// Регулярное выражение для проверки доменного имени
	var domainRegexp = regexp.MustCompile(`^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$`)
	return domainRegexp.MatchString(domain)
}
