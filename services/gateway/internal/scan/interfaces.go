package scan

type Usecase interface {
	DetermineInputType(input string) (string, error)
}

type Repo interface {
}
