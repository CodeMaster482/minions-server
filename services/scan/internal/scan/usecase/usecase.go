package usecase

type Usecase struct {
}

func NewUsecase() *Usecase {
	return &Usecase{}
}

func (uc *Usecase) AddAddress() error {
	panic("implement me")
	return nil
}
