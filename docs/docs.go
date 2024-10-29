// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {
            "name": "Dima",
            "url": "http://t.me/BelozerovD"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/api/scan/file": {
            "post": {
                "description": "Эндпоинт для сканирования файла и получения базового отчета от API Kaspersky.",
                "consumes": [
                    "multipart/form-data"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Scan"
                ],
                "summary": "Сканирует файл с использованием API Kaspersky",
                "operationId": "file-scan",
                "parameters": [
                    {
                        "type": "file",
                        "description": "File to scan",
                        "name": "file",
                        "in": "formData",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Successful scan. Returns basic information about the analyzed file.",
                        "schema": {
                            "$ref": "#/definitions/models.FileScanResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request: Failed to process the uploaded file.",
                        "schema": {
                            "$ref": "#/definitions/common.ErrorResponse"
                        }
                    },
                    "401": {
                        "description": "Unauthorized: Authentication failed.",
                        "schema": {
                            "$ref": "#/definitions/common.ErrorResponse"
                        }
                    },
                    "413": {
                        "description": "Payload Too Large: File size exceeds the 256 Mb limit.",
                        "schema": {
                            "$ref": "#/definitions/common.ErrorResponse"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error: Unable to process the file.",
                        "schema": {
                            "$ref": "#/definitions/common.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/api/scan/uri": {
            "get": {
                "description": "Эндпоинт для проверки веб-адреса, IP или домена и получения объединенного ответа с информацией из Kaspersky API.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Scan"
                ],
                "summary": "Проверка веб-адреса, IP или домена через Kaspersky API",
                "operationId": "domain-check",
                "parameters": [
                    {
                        "type": "string",
                        "example": "www.example.com",
                        "description": "Веб-адрес, IP или домен для проверки",
                        "name": "request",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Успешная проверка. Возвращается объединенный ответ с информацией.",
                        "schema": {
                            "$ref": "#/definitions/models.ResponseFromAPI"
                        }
                    },
                    "400": {
                        "description": "Bad Request: Incorrect query.",
                        "schema": {
                            "$ref": "#/definitions/common.ErrorResponse"
                        }
                    },
                    "404": {
                        "description": "Not Found: Lookup results not found.",
                        "schema": {
                            "$ref": "#/definitions/common.ErrorResponse"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/common.ErrorResponse"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "common.ErrorResponse": {
            "type": "object",
            "properties": {
                "message": {
                    "description": "Сообщение об ошибке",
                    "type": "string"
                }
            }
        },
        "models.AsnInfo": {
            "type": "object",
            "properties": {
                "Description": {
                    "description": "Описание автономной системы",
                    "type": "string",
                    "example": "Example ISP"
                },
                "Number": {
                    "description": "Номер автономной системы",
                    "type": "string",
                    "example": "AS12345"
                }
            }
        },
        "models.CategoryWithZone": {
            "type": "object",
            "properties": {
                "Name": {
                    "description": "Название категории",
                    "type": "string",
                    "example": "Phishing URL"
                },
                "Zone": {
                    "description": "Цвет зоны",
                    "type": "string",
                    "example": "Red"
                }
            }
        },
        "models.Contact": {
            "type": "object",
            "properties": {
                "ContactType": {
                    "description": "Тип контакта",
                    "type": "string",
                    "example": "registrant"
                },
                "Organization": {
                    "description": "Организация",
                    "type": "string",
                    "example": "YANDEX, LLC."
                }
            }
        },
        "models.DetectionInfo": {
            "type": "object",
            "properties": {
                "DescriptionUrl": {
                    "description": "Ссылка на описание обнаруженного объекта на сайте угроз Kaspersky (если доступно)",
                    "type": "string",
                    "example": "https://threats.kaspersky.com/en/threat/DetectedObject"
                },
                "DetectionMethod": {
                    "description": "Метод, использованный для обнаружения объекта",
                    "type": "string",
                    "example": "Signature"
                },
                "DetectionName": {
                    "description": "Название обнаруженного объекта",
                    "type": "string",
                    "example": "Trojan.Win32.Malware"
                },
                "LastDetectDate": {
                    "description": "Дата и время последнего обнаружения объекта экспертными системами Kaspersky",
                    "type": "string",
                    "example": "2022-10-01T00:00:00Z"
                },
                "Zone": {
                    "description": "Цвет зоны, к которой принадлежит обнаруженный объект",
                    "type": "string",
                    "example": "Red"
                }
            }
        },
        "models.DomainGeneralInfo": {
            "type": "object",
            "properties": {
                "Categories": {
                    "description": "Список категорий",
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "example": [
                        "[\"Malicious DomainIPUrl\"]"
                    ]
                },
                "CategoriesWithZone": {
                    "description": "Список категорий с зонами",
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/models.CategoryWithZone"
                    }
                },
                "Domain": {
                    "description": "Запрошенный домен",
                    "type": "string",
                    "example": "ya.ru"
                },
                "FilesCount": {
                    "description": "Количество известных вредоносных файлов",
                    "type": "integer",
                    "example": 5
                },
                "HitsCount": {
                    "description": "Количество IP адресов, связанных с доменом",
                    "type": "integer",
                    "example": 10
                },
                "Ipv4Count": {
                    "description": "Количество IPv4 адресов",
                    "type": "integer",
                    "example": 205
                },
                "UrlsCount": {
                    "description": "Количество известных вредоносных URL",
                    "type": "integer",
                    "example": 3
                }
            }
        },
        "models.DynamicDetection": {
            "type": "object",
            "properties": {
                "Threat": {
                    "description": "Количество обнаруженных объектов, принадлежащих к данной зоне",
                    "type": "integer",
                    "example": 1
                },
                "Zone": {
                    "description": "Цвет зоны обнаруженного объекта (Red или Yellow)",
                    "type": "string",
                    "example": "Red"
                }
            }
        },
        "models.FileGeneralInfo": {
            "type": "object",
            "properties": {
                "FileStatus": {
                    "description": "Статус отправленного файла (Malware, Adware and other, Clean, No threats detected, или Not categorized)",
                    "type": "string",
                    "example": "Malware"
                },
                "FirstSeen": {
                    "description": "Дата и время, когда файл был впервые обнаружен экспертными системами Kaspersky",
                    "type": "string",
                    "example": "2022-01-01T00:00:00Z"
                },
                "HitsCount": {
                    "description": "Количество обращений (популярность) проанализированного файла, обнаруженных экспертными системами Kaspersky",
                    "type": "integer",
                    "example": 100
                },
                "LastSeen": {
                    "description": "Дата и время последнего обнаружения файла экспертными системами Kaspersky",
                    "type": "string",
                    "example": "2022-10-01T00:00:00Z"
                },
                "Md5": {
                    "description": "MD5 хеш проанализированного файла",
                    "type": "string",
                    "example": "def456..."
                },
                "Packer": {
                    "description": "Название упаковщика (если доступно)",
                    "type": "string",
                    "example": "UPX"
                },
                "Sha1": {
                    "description": "SHA1 хеш проанализированного файла",
                    "type": "string",
                    "example": "abc123..."
                },
                "Sha256": {
                    "description": "SHA256 хеш проанализированного файла",
                    "type": "string",
                    "example": "ghi789..."
                },
                "Signer": {
                    "description": "Организация, подписавшая проанализированный файл",
                    "type": "string",
                    "example": "Example Corp"
                },
                "Size": {
                    "description": "Размер проанализированного файла (в байтах)",
                    "type": "integer",
                    "example": 123456
                },
                "Type": {
                    "description": "Тип проанализированного файла",
                    "type": "string",
                    "example": "Executable"
                }
            }
        },
        "models.FileScanResponse": {
            "type": "object",
            "properties": {
                "DetectionsInfo": {
                    "description": "Информация о обнаруженных объектах",
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/models.DetectionInfo"
                    }
                },
                "DynamicDetections": {
                    "description": "Обнаружения, связанные с проанализированным файлом",
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/models.DynamicDetection"
                    }
                },
                "FileGeneralInfo": {
                    "description": "Общая информация о проанализированном файле",
                    "allOf": [
                        {
                            "$ref": "#/definitions/models.FileGeneralInfo"
                        }
                    ]
                },
                "Zone": {
                    "description": "Цвет зоны, к которой принадлежит файл. Возможные значения: Red, Yellow, Green, Grey",
                    "type": "string",
                    "example": "Red"
                }
            }
        },
        "models.IpGeneralInfo": {
            "type": "object",
            "properties": {
                "Categories": {
                    "description": "Список категорий",
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "example": [
                        "[\"Malicious IP\"]"
                    ]
                },
                "CategoriesWithZone": {
                    "description": "Список категорий с зонами",
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/models.CategoryWithZone"
                    }
                },
                "CountryCode": {
                    "description": "Код страны (ISO 3166-1 alpha-2)",
                    "type": "string",
                    "example": "US"
                },
                "FirstSeen": {
                    "description": "Дата и время первого появления",
                    "type": "string",
                    "example": "2022-01-01T00:00:00Z"
                },
                "HitsCount": {
                    "description": "Количество обращений (популярность)",
                    "type": "integer",
                    "example": 15
                },
                "Ip": {
                    "description": "Запрошенный IP адрес",
                    "type": "string",
                    "example": "192.0.2.1"
                },
                "Status": {
                    "description": "Статус IP адреса (например, known, reserved)",
                    "type": "string",
                    "example": "known"
                }
            }
        },
        "models.IpWhoIs": {
            "type": "object",
            "properties": {
                "Asn": {
                    "description": "Информация об автономных системах",
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/models.AsnInfo"
                    }
                },
                "Net": {
                    "description": "Информация о сети",
                    "allOf": [
                        {
                            "$ref": "#/definitions/models.NetInfo"
                        }
                    ]
                }
            }
        },
        "models.NetInfo": {
            "type": "object",
            "properties": {
                "Changed": {
                    "description": "Дата последнего изменения",
                    "type": "string",
                    "example": "2020-01-01T00:00:00Z"
                },
                "Created": {
                    "description": "Дата создания",
                    "type": "string",
                    "example": "2019-01-01T00:00:00Z"
                },
                "Description": {
                    "description": "Описание сети",
                    "type": "string",
                    "example": "Example network description"
                },
                "Name": {
                    "description": "Название сети",
                    "type": "string",
                    "example": "EXAMPLE-NET"
                },
                "RangeEnd": {
                    "description": "Конечный IP адрес диапазона",
                    "type": "string",
                    "example": "192.0.2.255"
                },
                "RangeStart": {
                    "description": "Начальный IP адрес диапазона",
                    "type": "string",
                    "example": "192.0.2.0"
                }
            }
        },
        "models.Registrar": {
            "type": "object",
            "properties": {
                "IanaId": {
                    "description": "IANA ID",
                    "type": "string",
                    "example": "1234"
                },
                "Info": {
                    "description": "Название регистратора",
                    "type": "string",
                    "example": "RU-CENTER-RU"
                }
            }
        },
        "models.ResponseFromAPI": {
            "type": "object",
            "properties": {
                "Categories": {
                    "description": "Список категорий",
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "example": [
                        "[\"Phishing URL\"]"
                    ]
                },
                "CategoriesWithZone": {
                    "description": "Список категорий с зонами",
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/models.CategoryWithZone"
                    }
                },
                "DomainGeneralInfo": {
                    "description": "Информация о домене (если применимо)",
                    "allOf": [
                        {
                            "$ref": "#/definitions/models.DomainGeneralInfo"
                        }
                    ]
                },
                "DomainWhoIsInfo": {
                    "$ref": "#/definitions/models.WhoIsInfo"
                },
                "IpGeneralInfo": {
                    "description": "Информация об IP (если применимо)",
                    "allOf": [
                        {
                            "$ref": "#/definitions/models.IpGeneralInfo"
                        }
                    ]
                },
                "IpWhoIs": {
                    "description": "WHOIS информация об IP (если применимо)",
                    "allOf": [
                        {
                            "$ref": "#/definitions/models.IpWhoIs"
                        }
                    ]
                },
                "UrlDomainWhoIs": {
                    "description": "WHOIS информация об URL или домене (если применимо)",
                    "allOf": [
                        {
                            "$ref": "#/definitions/models.WhoIsInfo"
                        }
                    ]
                },
                "UrlGeneralInfo": {
                    "description": "Информация об URL (если применимо)",
                    "allOf": [
                        {
                            "$ref": "#/definitions/models.UrlGeneralInfo"
                        }
                    ]
                },
                "Zone": {
                    "description": "Цвет зоны: Red, Green, Grey",
                    "type": "string",
                    "example": "Red"
                }
            }
        },
        "models.UrlGeneralInfo": {
            "type": "object",
            "properties": {
                "Categories": {
                    "description": "Список категорий",
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "example": [
                        "[\"Phishing URL\"]"
                    ]
                },
                "CategoriesWithZone": {
                    "description": "Список категорий с зонами",
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/models.CategoryWithZone"
                    }
                },
                "FilesCount": {
                    "description": "Количество известных вредоносных файлов",
                    "type": "integer",
                    "example": 2
                },
                "Host": {
                    "description": "Хост URL",
                    "type": "string",
                    "example": "malicious.example.com"
                },
                "Ipv4Count": {
                    "description": "Количество IPv4 адресов",
                    "type": "integer",
                    "example": 1
                },
                "Url": {
                    "description": "Запрошенный URL",
                    "type": "string",
                    "example": "http://malicious.example.com"
                }
            }
        },
        "models.WhoIsInfo": {
            "type": "object",
            "properties": {
                "Contacts": {
                    "description": "Контактная информация",
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/models.Contact"
                    }
                },
                "Created": {
                    "description": "Дата создания",
                    "type": "string",
                    "example": "1999-07-11T20:00:00Z"
                },
                "DomainName": {
                    "description": "Имя домена",
                    "type": "string",
                    "example": "ya.ru"
                },
                "DomainStatus": {
                    "description": "Статусы домена",
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "example": [
                        "[\"REGISTERED",
                        " DELEGATED",
                        " VERIFIED\"]"
                    ]
                },
                "Expires": {
                    "description": "Дата истечения",
                    "type": "string",
                    "example": "2025-07-30T21:00:00Z"
                },
                "NameServers": {
                    "description": "Сервера имен",
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "example": [
                        "[\"ns1.yandex.ru\"",
                        " \"ns2.yandex.ru\"]"
                    ]
                },
                "Registrar": {
                    "description": "Информация о регистраторе",
                    "allOf": [
                        {
                            "$ref": "#/definitions/models.Registrar"
                        }
                    ]
                },
                "RegistrationOrganization": {
                    "description": "Организация регистрации",
                    "type": "string",
                    "example": "RU-CENTER-RU"
                },
                "Updated": {
                    "description": "Дата последнего обновления",
                    "type": "string",
                    "example": "2021-01-01T00:00:00Z"
                }
            }
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "",
	Host:             "",
	BasePath:         "",
	Schemes:          []string{},
	Title:            "Minions API",
	Description:      "API server for Minions.",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
