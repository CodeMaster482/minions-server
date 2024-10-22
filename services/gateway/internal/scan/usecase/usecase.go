package usecase

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
)

type Usecase struct {
}

func New() *Usecase {
	return &Usecase{}
}

// DetermineInputType определяет тип входной строки: IP, URL или домен.
func (uc *Usecase) DetermineInputType(input string) (string, error) {
	// Удаляем возможные пробелы по краям строки
	input = strings.TrimSpace(input)

	// Проверяем, является ли входная строка IP-адресом
	if net.ParseIP(input) != nil {
		return "ip", nil
	}

	// Проверяем, является ли входная строка URL
	u, err := url.Parse(input)
	if err == nil && u.Scheme != "" && u.Host != "" {
		// Проверяем, есть ли путь, отличный от пустого или "/"
		if u.Path != "" && u.Path != "/" {
			return "url", nil
		}
		// Если путь пустой или "/", считаем это доменом
		return "domain", nil
	}

	// Проверяем, является ли входная строка доменным именем
	if isValidDomain(input) {
		return "domain", nil
	}

	return "", errors.New("invalid input")
}

// isValidDomain проверяет, является ли строка валидным доменным именем.
func isValidDomain(domain string) bool {
	// Регулярное выражение для проверки доменного имени
	var domainRegexp = regexp.MustCompile(`^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$`)
	return domainRegexp.MatchString(domain)
}
