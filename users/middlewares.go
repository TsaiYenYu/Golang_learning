package users

import (
	"fmt"

	"github.com/TsaiYenYu/Golang_learning/common"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/golang-jwt/jwt/v4/request"
)

// A helper to write user_id and user_model to the context
func UpdateContextUserModel(c *gin.Context, my_user_id uint) {
	var myUserModel UserModel
	if my_user_id != 0 {
		db := common.GetDB()
		db.First(&myUserModel, my_user_id)
	}
	c.Set("my_user_id", my_user_id)
	c.Set("my_user_model", myUserModel)
}

// You can custom middlewares yourself as the doc: https://github.com/gin-gonic/gin#custom-middleware
//
//	r.Use(AuthMiddleware(true))
func AuthMiddleware(auto401 bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		UpdateContextUserModel(c, 0)

		token, err := request.ParseFromRequest(c.Request, request.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {

			return []byte(common.JwtKeyString), nil
		})
		// fmt.Println(err)

		if err != nil {
			if auto401 {
				// c.AbortWithError(http.StatusUnauthorized, err)
			} else {
				return
			}
		}

		userID, _, err := common.ValidateToken(token.Raw)
		if err != nil {
			// c.AbortWithError(http.StatusUnauthorized, err)
		}
		fmt.Println(userID)

		UpdateContextUserModel(c, userID)
	}
}
