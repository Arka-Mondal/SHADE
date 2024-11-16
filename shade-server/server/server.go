package server

import (
	"github.com/gin-gonic/gin"
	"shade-server/types"
)

func NewServer(db types.Database) *Server {
	router := gin.Default()
	server := &Server{
		db:     db,
		router: router,
	}

	// Setup routes
	router.POST("/api/v1/challenge", server.handleChallenge)
	router.POST("/api/v1/verify", server.handleVerify)

	return server
}

func (s *Server) Start(addr string) error {
	return s.router.Run(addr)
}
