package proto

import fmt "fmt"

var (
	ip      = "localhost"
	port    = "50052"
	address = fmt.Sprintf("%s:%s", ip, port)
)

type config struct {
	IP      string
	Port    string
	Address string
}

/*
GetSettings default settings for service
*/
func GetSettings() config {

	cnf := config{
		IP:      ip,
		Port:    port,
		Address: address,
	}

	return cnf
}
