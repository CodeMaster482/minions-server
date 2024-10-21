package models

// FileScanResponse представляет ответ от Kaspersky API для сканирования файла
type FileScanResponse struct {
	// Цвет зоны, к которой принадлежит файл. Возможные значения: Red, Yellow, Green, Grey
	Zone string `json:"Zone" example:"Red"`

	// Общая информация о проанализированном файле
	FileGeneralInfo *FileGeneralInfo `json:"FileGeneralInfo,omitempty"`

	// Информация о обнаруженных объектах
	DetectionsInfo []DetectionInfo `json:"DetectionsInfo,omitempty"`

	// Обнаружения, связанные с проанализированным файлом
	DynamicDetections []DynamicDetection `json:"DynamicDetections,omitempty"`
}

// FileGeneralInfo представляет общую информацию о проанализированном файле
type FileGeneralInfo struct {
	// Статус отправленного файла (Malware, Adware and other, Clean, No threats detected, или Not categorized)
	FileStatus string `json:"FileStatus" example:"Malware"`

	// SHA1 хеш проанализированного файла
	Sha1 string `json:"Sha1" example:"abc123..."`

	// MD5 хеш проанализированного файла
	Md5 string `json:"Md5" example:"def456..."`

	// SHA256 хеш проанализированного файла
	Sha256 string `json:"Sha256" example:"ghi789..."`

	// Дата и время, когда файл был впервые обнаружен экспертными системами Kaspersky
	FirstSeen string `json:"FirstSeen" example:"2022-01-01T00:00:00Z"`

	// Дата и время последнего обнаружения файла экспертными системами Kaspersky
	LastSeen string `json:"LastSeen" example:"2022-10-01T00:00:00Z"`

	// Организация, подписавшая проанализированный файл
	Signer string `json:"Signer,omitempty" example:"Example Corp"`

	// Название упаковщика (если доступно)
	Packer string `json:"Packer,omitempty" example:"UPX"`

	// Размер проанализированного файла (в байтах)
	Size int64 `json:"Size" example:"123456"`

	// Тип проанализированного файла
	Type string `json:"Type" example:"Executable"`

	// Количество обращений (популярность) проанализированного файла, обнаруженных экспертными системами Kaspersky
	HitsCount int `json:"HitsCount" example:"100"`
}

// DetectionInfo представляет информацию об обнаруженных объектах
type DetectionInfo struct {
	// Дата и время последнего обнаружения объекта экспертными системами Kaspersky
	LastDetectDate string `json:"LastDetectDate" example:"2022-10-01T00:00:00Z"`

	// Ссылка на описание обнаруженного объекта на сайте угроз Kaspersky (если доступно)
	DescriptionUrl string `json:"DescriptionUrl,omitempty" example:"https://threats.kaspersky.com/en/threat/DetectedObject"`

	// Цвет зоны, к которой принадлежит обнаруженный объект
	Zone string `json:"Zone" example:"Red"`

	// Название обнаруженного объекта
	DetectionName string `json:"DetectionName" example:"Trojan.Win32.Malware"`

	// Метод, использованный для обнаружения объекта
	DetectionMethod string `json:"DetectionMethod" example:"Signature"`
}

// DynamicDetection представляет обнаружения, связанные с проанализированным файлом
type DynamicDetection struct {
	// Цвет зоны обнаруженного объекта (Red или Yellow)
	Zone string `json:"Zone" example:"Red"`

	// Количество обнаруженных объектов, принадлежащих к данной зоне
	Threat int `json:"Threat" example:"1"`
}
