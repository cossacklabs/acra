package firewall

type Firewall struct {

	handlers []QueryHandlerInterface
}

func (firewall *Firewall) AddHandler(handler QueryHandlerInterface){

	firewall.handlers = append(firewall.handlers, handler)
}

func (firewall *Firewall) RemoveHandler(handler QueryHandlerInterface){
	for index, handlerFromRange := range firewall.handlers{
		if handlerFromRange == handler {
			firewall.handlers = append(firewall.handlers[:index], firewall.handlers[index+1:]...)
		}
	}
}

func (firewall *Firewall) HandleQuery(query string) error{

	for _, handler := range firewall.handlers{
		if err := handler.CheckQuery(query); err != nil{
			return err
		}
	}
	return nil
}
