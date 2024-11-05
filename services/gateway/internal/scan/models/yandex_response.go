package models

type TextAnnotation struct {
	FullText string `json:'full_text'`
}

type Result struct {
	TextAnnotation TextAnnotation `json:'text_annotation'`
}

type ApiResponse struct {
	Result Result `json:'result'`
}
