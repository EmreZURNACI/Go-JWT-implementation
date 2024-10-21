package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

type Auth struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type Header struct {
	Alg  string `json:"alg"`
	Type string `json:"type"`
}

const SECRET_KEY string = "supersecretkey12345"

func main() {
	_mux := mux.NewRouter()
	var a Auth
	_mux.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Fprintln(w, "Body boş olamaz")
			return
		}
		err = json.Unmarshal(body, &a)
		if err != nil {
			fmt.Fprintln(w, "Body geçersiz")
			return
		}
		if a.Email != "emrezurnaci@gmail.com" || a.Password != "123" {
			fmt.Fprintln(w, "Şifre veya e-posta yanlış")
			return
		}
		token, err := CreateToken(SECRET_KEY, a.Email)
		if err != nil {
			fmt.Fprintln(w, err)
			return
		}
		c := &http.Cookie{
			Name:     "Token",
			Value:    token,
			Path:     "/",
			Domain:   "localhost",
			HttpOnly: false,
			Secure:   false,
			MaxAge:   3600,
			Expires:  time.Now().Add(3600 * time.Second),
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, c)
		fmt.Fprintln(w, "Giriş başarılı")
	}).Methods(http.MethodPost, http.MethodGet, http.MethodOptions)

	_mux.HandleFunc("/product", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "Bearer " || authHeader == "undefined" || authHeader == "Bearer undefined" {
			fmt.Fprintln(w, "Unauthorizated")
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		valid, err := ValidateToken(tokenString, a.Email)
		if err != nil || valid == nil {
			fmt.Fprintln(w, "Unauthorizated")
			return
		}
		fmt.Fprintln(w, "Ürünler getiriliyor")
	}).Methods(http.MethodPost, http.MethodGet, http.MethodOptions)

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowedMethods:   []string{http.MethodGet, http.MethodOptions, http.MethodPost},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	})
	handler := c.Handler(_mux)
	http.ListenAndServe(":8080", handler)
}

func CreateToken(secretKey string, email string) (string, error) {
	// JWT Header
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	// Header'ı JSON formatında encode et
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	// JWT Payload
	claims := jwt.MapClaims{
		"exp":  time.Now().Add(time.Hour * 2).Unix(),
		"iat":  time.Now().Unix(),
		"user": email,
	}

	// Payload'ı JSON formatında encode et
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Signature oluştur
	signatureInput := fmt.Sprintf("%s.%s", headerEncoded, claimsEncoded)
	signature, err := jwt.SigningMethodHS256.Sign(signatureInput, []byte(secretKey))
	if err != nil {
		return "", err
	}
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	// Sonuç: Header, Payload ve Signature birleştir
	return fmt.Sprintf("%s.%s.%s", headerEncoded, claimsEncoded, signatureEncoded), nil
}

func ValidateToken(tokenString string, email string) (*jwt.Token, error) {
	claims := jwt.MapClaims{
		"exp":  time.Now().Add(time.Hour * 2).Unix(),
		"iat":  time.Now().Unix(),
		"user": email,
	}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(SECRET_KEY), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}
