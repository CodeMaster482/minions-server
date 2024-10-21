package models

// ResponseFromAPI представляет объединенный ответ от Kaspersky API
type ResponseFromAPI struct {
	// Цвет зоны: Red, Green, Grey
	Zone string `json:"Zone" example:"Red"`

	// Список категорий
	Categories []string `json:"Categories,omitempty" example:"[\"Phishing URL\"]"`

	// Список категорий с зонами
	CategoriesWithZone []CategoryWithZone `json:"CategoriesWithZone,omitempty"`

	// Информация об URL (если применимо)
	UrlGeneralInfo *UrlGeneralInfo `json:"UrlGeneralInfo,omitempty"`

	// Информация о домене (если применимо)
	DomainGeneralInfo *DomainGeneralInfo `json:"DomainGeneralInfo,omitempty"`

	// Информация об IP (если применимо)
	IpGeneralInfo *IpGeneralInfo `json:"IpGeneralInfo,omitempty"`

	// WHOIS информация об URL или домене (если применимо)
	UrlDomainWhoIs  *WhoIsInfo `json:"UrlDomainWhoIs,omitempty"`
	DomainWhoIsInfo *WhoIsInfo `json:"DomainWhoIsInfo,omitempty"`

	// WHOIS информация об IP (если применимо)
	IpWhoIs *IpWhoIs `json:"IpWhoIs,omitempty"`
}

// CategoryWithZone представляет категорию и ее зону
type CategoryWithZone struct {
	// Название категории
	Name string `json:"Name" example:"Phishing URL"`

	// Цвет зоны
	Zone string `json:"Zone" example:"Red"`
}

// UrlGeneralInfo представляет общую информацию об URL
type UrlGeneralInfo struct {
	// Запрошенный URL
	Url string `json:"Url" example:"http://malicious.example.com"`

	// Хост URL
	Host string `json:"Host" example:"malicious.example.com"`

	// Количество IPv4 адресов
	Ipv4Count int `json:"Ipv4Count" example:"1"`

	// Количество известных вредоносных файлов
	FilesCount int `json:"FilesCount" example:"2"`

	// Список категорий
	Categories []string `json:"Categories,omitempty" example:"[\"Phishing URL\"]"`

	// Список категорий с зонами
	CategoriesWithZone []CategoryWithZone `json:"CategoriesWithZone,omitempty"`
}

// DomainGeneralInfo представляет общую информацию о домене
type DomainGeneralInfo struct {
	// Количество известных вредоносных файлов
	FilesCount int `json:"FilesCount" example:"5"`

	// Количество известных вредоносных URL
	UrlsCount int `json:"UrlsCount" example:"3"`

	// Количество IP адресов, связанных с доменом
	HitsCount int `json:"HitsCount" example:"10"`

	// Запрошенный домен
	Domain string `json:"Domain" example:"ya.ru"`

	// Количество IPv4 адресов
	Ipv4Count int `json:"Ipv4Count" example:"205"`

	// Список категорий
	Categories []string `json:"Categories,omitempty" example:"[\"Malicious DomainIPUrl\"]"`

	// Список категорий с зонами
	CategoriesWithZone []CategoryWithZone `json:"CategoriesWithZone,omitempty"`
}

// IpGeneralInfo представляет общую информацию об IP адресе
type IpGeneralInfo struct {
	// Статус IP адреса (например, known, reserved)
	Status string `json:"Status" example:"known"`

	// Код страны (ISO 3166-1 alpha-2)
	CountryCode string `json:"CountryCode" example:"US"`

	// Количество обращений (популярность)
	HitsCount int `json:"HitsCount" example:"15"`

	// Дата и время первого появления
	FirstSeen string `json:"FirstSeen" example:"2022-01-01T00:00:00Z"`

	// Запрошенный IP адрес
	Ip string `json:"Ip" example:"192.0.2.1"`

	// Список категорий
	Categories []string `json:"Categories,omitempty" example:"[\"Malicious IP\"]"`

	// Список категорий с зонами
	CategoriesWithZone []CategoryWithZone `json:"CategoriesWithZone,omitempty"`
}

// Contact представляет контактную информацию
type Contact struct {
	// Тип контакта
	ContactType string `json:"ContactType" example:"registrant"`

	// Организация
	Organization string `json:"Organization" example:"YANDEX, LLC."`
}

// WhoIsInfo представляет WHOIS информацию для домена или URL
type WhoIsInfo struct {
	// Имя домена
	DomainName string `json:"DomainName" example:"ya.ru"`

	// Дата создания
	Created string `json:"Created" example:"1999-07-11T20:00:00Z"`

	// Дата последнего обновления
	Updated string `json:"Updated" example:"2021-01-01T00:00:00Z"`

	// Дата истечения
	Expires string `json:"Expires" example:"2025-07-30T21:00:00Z"`

	// Сервера имен
	NameServers []string `json:"NameServers,omitempty" example:"[\"ns1.yandex.ru\", \"ns2.yandex.ru\"]"`

	// Контактная информация
	Contacts []Contact `json:"Contacts,omitempty"`

	// Информация о регистраторе
	Registrar *Registrar `json:"Registrar,omitempty"`

	// Статусы домена
	DomainStatus []string `json:"DomainStatus,omitempty" example:"[\"REGISTERED, DELEGATED, VERIFIED\"]"`

	// Организация регистрации
	RegistrationOrganization string `json:"RegistrationOrganization" example:"RU-CENTER-RU"`
}

// Registrar представляет информацию о регистраторе
type Registrar struct {
	// Название регистратора
	Info string `json:"Info" example:"RU-CENTER-RU"`

	// IANA ID
	IanaId string `json:"IanaId" example:"1234"`
}

// IpWhoIs представляет WHOIS информацию для IP адреса
type IpWhoIs struct {
	// Информация об автономных системах
	Asn []AsnInfo `json:"Asn,omitempty"`

	// Информация о сети
	Net *NetInfo `json:"Net,omitempty"`
}

// AsnInfo представляет информацию об автономной системе
type AsnInfo struct {
	// Номер автономной системы
	Number string `json:"Number" example:"AS12345"`

	// Описание автономной системы
	Description string `json:"Description" example:"Example ISP"`
}

// NetInfo представляет информацию о сети
type NetInfo struct {
	// Начальный IP адрес диапазона
	RangeStart string `json:"RangeStart" example:"192.0.2.0"`

	// Конечный IP адрес диапазона
	RangeEnd string `json:"RangeEnd" example:"192.0.2.255"`

	// Дата создания
	Created string `json:"Created" example:"2019-01-01T00:00:00Z"`

	// Дата последнего изменения
	Changed string `json:"Changed" example:"2020-01-01T00:00:00Z"`

	// Название сети
	Name string `json:"Name" example:"EXAMPLE-NET"`

	// Описание сети
	Description string `json:"Description" example:"Example network description"`
}
