package models

const (
	ScanScreenNotFoundIOC = "not found in screen"
)

const (
	MissingRequestParam      = "Missing 'request' query parameter"
	InvalidInput             = "Invalid input"
	FailedToEncodeResponse   = "Failed to encode response"
	KasperskyUnexpectedError = "Kaspersky API returned unexpected error"

	BadRequestMsg          = "Bad Request: Incorrect query."
	UnauthorizedMsg        = "Unauthorized: Authentication failed."
	InternalServerErrorMsg = "Internal Server Error"

	ScanFileBadRequestMsg          = "Bad Request: Failed to process the uploaded file."
	ScanFilePayloadTooLargeMsg     = "Payload Too Large: File size exceeds the 256 MB limit."
	ScanFileInternalServerErrorMsg = "Internal Server Error: Unable to process the file."
)
