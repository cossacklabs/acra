package http_api

type poisonCallback struct {
	Called bool
}

func (callback *poisonCallback) Call() error {
	callback.Called = true
	return nil
}
