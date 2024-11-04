package models

type Vertex struct {
	X int `json:"x"`
	Y int `json:"y"`
}

type BoundingBox struct {
	Vertices []Vertex `json:"vertices"`
}

type Word struct {
	BoundingBox BoundingBox `json:"bounding_box"`
	Text        string      `json:"text"`
}

type Alternative struct {
	Text  string `json:"text"`
	Words []Word `json:"words"`
}

type Line struct {
	BoundingBox  BoundingBox   `json:"bounding_box"`
	Alternatives []Alternative `json:"alternatives"`
}

type Block struct {
	BoundingBox BoundingBox `json:"bounding_box"`
	Lines       []Line      `json:"lines"`
}

type TextAnnotation struct {
	Width  string  `json:"width"`
	Height string  `json:"height"`
	Blocks []Block `json:"blocks"`
}

type Result struct {
	TextAnnotation TextAnnotation `json:"text_annotation"`
}

type OCRResponse struct {
	Result Result `json:"result"`
}
