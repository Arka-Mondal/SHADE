package server

import (
	"time"

	"github.com/gin-gonic/gin"
	"shade-server/types"
)

type Server struct {
	db     types.Database
	router *gin.Engine
}

type Config struct {
	MasterKey           []byte
	ChallengeExpiration time.Duration
	SessionExpiration   time.Duration
	ListenAddr          string
}

func DefaultConfig() *Config {
	return &Config{
		ChallengeExpiration: 5 * time.Minute,
		SessionExpiration:   24 * time.Hour,
		ListenAddr:          ":8080",
	}
}
