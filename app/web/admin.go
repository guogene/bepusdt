package web

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cast"

	"github.com/v03413/bepusdt/app/conf"
	"github.com/v03413/bepusdt/app/model"
)

type LoginForm struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func AdminLogin(c *gin.Context) {
	var form LoginForm
	if err := c.ShouldBindJSON(&form); err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 1, "message": "参数错误"})
		return
	}

	// 验证用户名密码
	auth := strings.Split(conf.GetAdminAuth(), ":")
	if len(auth) != 2 || form.Username != auth[0] || form.Password != auth[1] {
		c.JSON(http.StatusOK, gin.H{"code": 1, "message": "用户名或密码错误"})
		return
	}

	// 生成JWT Token
	claims := Claims{
		Username: form.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(base64.StdEncoding.EncodeToString([]byte(conf.GetAdminAuth()))))
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 1, "message": "生成Token失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{"token": tokenString},
	})
}

func AdminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if auth == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "未登录"})
			c.Abort()
			return
		}

		parts := strings.Split(auth, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "Token格式错误"})
			c.Abort()
			return
		}

		tokenString := parts[1]
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(base64.StdEncoding.EncodeToString([]byte(conf.GetAdminAuth()))), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "Token无效"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func GetOrders(c *gin.Context) {
	page := cast.ToInt(c.DefaultQuery("page", "1"))
	size := cast.ToInt(c.DefaultQuery("size", "10"))
	offset := (page - 1) * size

	var orders []model.TradeOrders
	var total int64

	model.DB.Model(&model.TradeOrders{}).Count(&total)
	model.DB.Order("created_at DESC").Offset(offset).Limit(size).Find(&orders)

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{
			"items": orders,
			"total": total,
		},
	})
}

func GetRecords(c *gin.Context) {
	page := cast.ToInt(c.DefaultQuery("page", "1"))
	size := cast.ToInt(c.DefaultQuery("size", "10"))
	offset := (page - 1) * size

	var records []model.NotifyRecord
	var total int64

	model.DB.Model(&model.NotifyRecord{}).Count(&total)
	model.DB.Order("created_at DESC").Offset(offset).Limit(size).Find(&records)

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{
			"items": records,
			"total": total,
		},
	})
}
