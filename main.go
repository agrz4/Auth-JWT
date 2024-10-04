package main

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var SECRET_KEY = []byte("kuncirahasia")

type (
	LoginPayload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	JwtTokenPayload struct {
		Username string `json:"username"`
		jwt.RegisteredClaims
	}

	Response struct {
		Status  int         `json:"Status"`
		Message string      `json:"message"`
		Data    interface{} `json:"data,omitempty"`
	}
)

func JwtMiddleware() echo.MiddlewareFunc {
	middleware.ErrJWTMissing.Code = http.StatusUnauthorized
	middleware.ErrJWTMissing.Message = "Unauthorized"

	return echojwt.WithConfig(echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(JwtTokenPayload)
		},
		SigningKey: SECRET_KEY,
	})
}

func main() {
	router := echo.New()
	router.POST("api/token", func(c echo.Context) error {
		loginPayload := new(LoginPayload)

		if err := c.Bind(loginPayload); err != nil {
			return c.JSON(http.StatusBadRequest, Response{
				Status:  http.StatusBadRequest,
				Message: "Invalid request payload",
			})
		}

		if loginPayload.Username == "admin" && loginPayload.Password == "admin" {
			var token JwtTokenPayload
			lifeTimeToken := 1

			now := time.Now()
			token.RegisteredClaims = jwt.RegisteredClaims{
				Issuer:    "my-app",
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour * time.Duration(lifeTimeToken))),
			}

			token.Username = loginPayload.Username
			_token := jwt.NewWithClaims(jwt.SigningMethodHS256, token)
			accessToken, err := _token.SignedString(SECRET_KEY)

			if err != nil {
				return c.JSON(http.StatusInternalServerError, Response{
					Status:  http.StatusInternalServerError,
					Message: "Failed to generate access token",
				})
			}

			return c.JSON(http.StatusOK, Response{
				Status: 200,
				Data: struct {
					AccessToken string `json:"access_token"`
				}{
					AccessToken: accessToken,
				},
			})
		} else {
			return c.JSON(http.StatusBadRequest, Response{
				Status:  http.StatusBadRequest,
				Message: "Invalid username or password",
			})
		}
	})

	router.GET("api/profile", func(c echo.Context) error {
		return c.JSON(http.StatusOK, Response{
			Status:  200,
			Message: "You are accessing this API using a valid JWT token",
		})
	}, JwtMiddleware())
	router.Start(":8080")
}
