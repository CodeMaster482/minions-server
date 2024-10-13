package models

// ResponseFromAPI представляет структуру ответа от Kaspersky API
type ResponseFromAPI struct {
	Zone              string `json:"zone"`
	DomainGeneralInfo struct {
		Domain string `json:"domain"`
		// Добавьте другие поля, если необходимо
	} `json:"domain_general_info"`
	// Добавьте другие необходимые поля из ответа API
}

// ResponseToClient представляет структуру ответа, отправляемого клиенту
type ResponseToClient struct {
	Color string `json:"color"`
	// Добавьте другие поля, если необходимо
}
