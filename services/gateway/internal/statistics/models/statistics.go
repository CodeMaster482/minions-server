package models

type LinkStat struct {
	Request     string `json:"request"`
	AccessCount int    `json:"access_count"`
}
