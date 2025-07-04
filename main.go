package main

import (
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"


	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type Design struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateAt:true"`
	UpdatedAt time.Time `json:"updated_at" gorm:"autoUpdateAt:true"`

	Name        string `json:"name" form:"name"`
	Description string `json:"description" form:"description"`
	ImageName   string `json:"image_name" form:"image_name"`
	Votes       uint   `json:"votes" form:"votes"`
	Author      string `json:"author" form:"author"`
}
type User struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateAt:true"`
	UpdatedAt time.Time `json:"updated_at" gorm:"autoUpdateAt:true"`

	Email    string `json:"email" form:"email" gorm:"unique"`
	Password string `json:"password" form:"password"`
	IsAdmin  bool   `json:"is_admin" form:"is_admin"`
	IsVoted  bool   `json:"is_voted" form:"is_voted"`
}
type CreateDesignDto struct {
	Author      string `json:"author" form:"author" binding:"required"`
	Name        string `json:"name" form:"name" binding:"required"`
	Description string `json:"description" form:"description" binding:"required"`
}

func secretKey() string {
	var SECRET_KEY string = os.Getenv("SECRET_KEY")
	return SECRET_KEY
}
func main() {

	// err := godotenv.Load(".env")
	secretKey()
	db, err := gorm.Open(mysql.Open(os.Getenv("DSN")), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
		panic("failed to connect database")
	}

	db.AutoMigrate(&Design{}, &User{})
	var user User
	db.First(&user, "email=?", os.Getenv("EMAIL"))
	if user.ID == 0 {
		hash, err := bcrypt.GenerateFromPassword([]byte(os.Getenv("PASSWORD")), 10)
		if err != nil {
			log.Fatal("failed to generate admin password")
		}
		db.Save(&User{
			Email:    os.Getenv("EMAIL"),
			Password: string(hash),
			IsAdmin:  true,
		})
	}
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.SetTrustedProxies([]string{"localhost"})
	configCors := cors.Config{}
	configCors.AllowOrigins = []string{
		"https://mahragan.leapcell.app"}
	configCors.AllowMethods = []string{"*"}
	configCors.AllowHeaders = []string{"*"}
	configCors.AllowCredentials = true
	router.Use(cors.New(configCors))
	router.Static("/images", "./images")
	router.GET("/", func(c *gin.Context) {
		var designs []Design
		db.Find(&designs)

		c.JSON(200, gin.H{
			"designs": designs,
		})
	})
	router.GET("/role", authenticate, func(c *gin.Context) {

		role, err := getRole(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer "))
		if err != nil {

			c.JSON(401, gin.H{
				"message": "Unauthorized",
			})
		}
		c.JSON(200, gin.H{
			"role": role,
		})

	})
	router.GET("/:id", func(c *gin.Context) {
		var design Design
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.JSON(404, gin.H{
				"message": "Not Found",
			})
		} else {
			db.First(&design, id)

			c.JSON(200, gin.H{
				"design": design,
			})
		}

	})
	router.PUT("/vote/:id", authenticate, func(c *gin.Context) {

		email, err := getSubject(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer "))
		if err != nil {
			c.JSON(401, gin.H{
				"message": "Unauthorized",
				"error":   "Error: " + err.Error(),
			})
		} else {
			id, _ := strconv.Atoi(c.Param("id"))
			var user User
			db.First(&user, "email=?", email)
			if !user.IsVoted {
				var design Design
				db.First(&design, id)
				db.Save(&Design{
					ID:          uint(id),
					Name:        design.Name,
					Description: design.Description,
					ImageName:   design.ImageName,
					Author:      design.Author,
					Votes:       design.Votes + 1,
				})
				db.Save(&User{
					ID:       user.ID,
					IsVoted:  true,
					Password: user.Password,
					IsAdmin:  user.IsAdmin,
					Email:    email,
				})
				c.JSON(200, gin.H{
					"message": "Voted Successfully",
				})
			} else {

				c.JSON(400, gin.H{
					"message": "cannot vote more than one time",
				})
			}
		}
	})
	router.POST("/", isAdminAuthenticate, func(c *gin.Context) {
		var data CreateDesignDto

		file, _ := c.FormFile("image")
		date := time.Now().String()
		var ImageName string = "images/" + date + "__" + file.Filename
		ImageName = strings.ReplaceAll(ImageName, " ", "-")
		ImageName = strings.ReplaceAll(ImageName, ":", "-")
		c.Bind(&data)
		c.SaveUploadedFile(file, "./"+ImageName)

		res := db.Create(&Design{
			Author:      data.Author,
			Name:        data.Name,
			Description: data.Description,
			ImageName:   ImageName,
		})
		if res.Error != nil {

			c.JSON(400, gin.H{
				"message": "There is Error while creating it",
			})

		} else {

			c.JSON(201, gin.H{
				"message": "Created Successfully",
			})
		}

	})
	router.PUT("/:id", isAdminAuthenticate, func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		var data CreateDesignDto
		date := time.RFC3339
		file, _ := c.FormFile("image")

		if file != nil && file.Filename != "" {
			var old Design
			db.First(&old, id)
			os.Remove(old.ImageName)
		}
		var ImageName string = "images/" + date + "__" + file.Filename
		ImageName = strings.ReplaceAll(ImageName, " ", "-")
		ImageName = strings.ReplaceAll(ImageName, ":", "-")

		c.Bind(&data)
		c.SaveUploadedFile(file, "./"+ImageName)
		res := db.Save(&Design{
			Author:      data.Author,
			Name:        data.Name,
			Description: data.Description,
			ImageName:   ImageName,
			ID:          uint(id),
		})
		if res.Error != nil {

			c.JSON(400, gin.H{
				"message": "There is Error while editing it",
			})

		} else {

			c.JSON(201, gin.H{
				"message": "Editied Successfully",
			})
		}
	})
	router.DELETE("/:id", isAdminAuthenticate, func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))

		var old Design
		db.First(&old, id)
		os.Remove(old.ImageName)

		db.Delete(&Design{}, id)
		c.JSON(204, gin.H{
			"messages": "Deleted Successfully",
		})
	})
	router.POST("/signup", func(c *gin.Context) {
		var data User
		c.Bind(&data)
		var myUser User
		db.First(&myUser, "email=?", data.Email)
		if myUser.ID == 0 {
			hash, _ := bcrypt.GenerateFromPassword([]byte(data.Password), 10)
			db.Create(&User{
				Email:    data.Email,
				Password: string(hash),
				IsAdmin:  false,
			})
			jwt, err := login(data.Email, data.Password, db)
			if err != nil {
				c.JSON(400, gin.H{
					"message": err.Error(),
				})
			} else {
				c.JSON(200, gin.H{
					"jwt": jwt,
				})
			}
		} else {
			c.JSON(400, gin.H{
				"message": "user already exist",
			})
		}
	})
	router.POST("/login", func(c *gin.Context) {
		var data User
		c.Bind(&data)
		jwt, err := login(data.Email, data.Password, db)
		if err != nil {
			c.JSON(400, gin.H{
				"message": err.Error(),
			})
		} else {
			c.JSON(200, gin.H{
				"jwt": jwt,
			})
		}

	})
	router.Run()
}
func login(email string, password string, db *gorm.DB) (string, error) {
	var user User
	db.First(&user, "email=?", email)

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return "", errors.New("wrong password")
	}
	role := "user"
	if user.IsAdmin {
		role = "admin"
	}
	claims := jwt.MapClaims{
		"sub": user.Email,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
		"iat": time.Now().Unix(),
		"aud": role,
	}
	jwt, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secretKey()))
	if err != nil {
		return "", errors.New("there is error in signing jwt")
	}
	return jwt, nil
}
func authenticate(c *gin.Context) {
	bearer := c.GetHeader("Authorization")
	if bearer == "" && !strings.HasPrefix(bearer, "Bearer ") {
		c.AbortWithStatus(401)

	}

	_, err := verifyToken(strings.TrimPrefix(bearer, "Bearer "))

	if err != nil {
		c.AbortWithError(401, errors.New("there is error while validating token: "+err.Error()))

	}
	c.Next()

}
func isAdminAuthenticate(c *gin.Context) {
	bearer := c.GetHeader("Authorization")
	if bearer == "" && !strings.HasPrefix(bearer, "Bearer ") {
		c.AbortWithStatus(401)

	}

	role, err := isAdmin(strings.TrimPrefix(bearer, "Bearer "))
	if err != nil {
		c.AbortWithStatus(401)
	}
	if role != "admin" {
		c.AbortWithStatus(401)
	}

	c.Next()
}

func verifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return []byte(secretKey()), nil
	})
	if err != nil {

		return nil, err
	}
	if !token.Valid {
		return nil, err
	}
	return token, nil
}

func isAdmin(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return []byte(secretKey()), nil
	})
	if err != nil {

		return "", err
	}
	if !token.Valid {
		return "", err
	}
	roles, err := token.Claims.GetAudience()
	if err != nil {

		return "", err
	}

	return roles[0], nil
}

func getSubject(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return []byte(secretKey()), nil
	})
	if err != nil {

		return "", err
	}
	email, err := token.Claims.GetSubject()
	if err != nil {

		return "", err
	}
	return email, nil

}

func getRole(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return []byte(secretKey()), nil
	})
	if err != nil {

		return "", err
	}
	roles, err := token.Claims.GetAudience()
	if err != nil {

		return "", err
	}
	return roles[0], nil

}
