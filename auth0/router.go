package auth0

import (
	"encoding/gob"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func RegisterRouter(router *gin.Engine, keyPair []byte) *gin.Engine {
	gob.Register(map[string]interface{}{})

	store := cookie.NewStore(keyPair)
	router.Use(sessions.Sessions("auth-session", store))

	return router
}
