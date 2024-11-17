package server

import (
	"net/http"
	"github.com/gin-gonic/gin"
	"github.com/rs/cors"
	"shade-server/types"
	"shade-server/blockchain"
)

func NewServer(db types.Database, contract *blockchain.IdentityRegistry) *Server {
	s := &Server{
		router:   gin.Default(),
		db:       db,
		contract: contract,
	}
	s.routes()
	return s
}

func (s *Server) Start(addr string) error {
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"http://localhost:3000"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
		Debug: true,
	})

	handler := c.Handler(s.router)

	return http.ListenAndServe(addr, handler)
}

func (s *Server) routes() {
	router := s.router

	// Setup routes
	router.POST("/shade/v1/authenticate", s.handleChallenge)
	router.POST("/shade/v1/verify", s.handleVerify)
}
