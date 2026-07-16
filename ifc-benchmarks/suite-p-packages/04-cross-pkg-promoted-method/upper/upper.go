package upper

import "cross-pkg-promoted-method/lower"

type Server struct {
	lower.Base
}

func New() Server {
	return Server{Base: lower.Base{}}
}
