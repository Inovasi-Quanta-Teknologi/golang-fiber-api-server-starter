package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	jwtware "github.com/gofiber/jwt/v3"
	"github.com/gofiber/fiber/v2/middleware/cors"
	fiberlogger "github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	limiter "github.com/gofiber/limiter/v2"
	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/golang-jwt/jwt/v5"
)

// ==================== Config & Setup ====================

type Config struct {
	Port        int
	JWTSecret   string
	DBUrl       string
	RateLimit   int           // requests per window
	RateWindow  time.Duration // window duration
	Env         string
	TokenExpiry time.Duration
}

func loadConfigFromEnv() (*Config, error) {
	port := 4000
	if p := os.Getenv("PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return nil, errors.New("JWT_SECRET is required")
	}
	dbUrl := os.Getenv("DATABASE_URL") // optional
	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "development"
	}
	rateLimit := 100
	if rl := os.Getenv("RATE_LIMIT"); rl != "" {
		if v, err := strconv.Atoi(rl); err == nil {
			rateLimit = v
		}
	}
	rateWindow := 1 * time.Minute
	if rw := os.Getenv("RATE_WINDOW_SEC"); rw != "" {
		if s, err := strconv.Atoi(rw); err == nil {
			rateWindow = time.Duration(s) * time.Second
		}
	}
	tokenExpiry := 24 * time.Hour
	if te := os.Getenv("TOKEN_EXPIRY_HOURS"); te != "" {
		if h, err := strconv.Atoi(te); err == nil {
			tokenExpiry = time.Duration(h) * time.Hour
		}
	}

	return &Config{
		Port:        port,
		JWTSecret:   jwtSecret,
		DBUrl:       dbUrl,
		RateLimit:   rateLimit,
		RateWindow:  rateWindow,
		Env:         env,
		TokenExpiry: tokenExpiry,
	}, nil
}

// ==================== Models ====================

type User struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Email     string    `gorm:"uniqueIndex;size:255" json:"email" validate:"required,email"`
	Password  string    `gorm:"size:255" json:"-"`
	Name      string    `gorm:"size:255" json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ==================== Request DTOs ====================

type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
	Name     string `json:"name" validate:"omitempty,min=2"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// ==================== Utilities ====================

var validate = validator.New()

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(hashed string, plain string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
}

func generateJWT(secret string, userID uint, expiry time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"sub": strconv.FormatUint(uint64(userID), 10),
		"exp": time.Now().Add(expiry).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func parseUserIDFromToken(c *fiber.Ctx) (uint, error) {
	user := c.Locals("user")
	if user == nil {
		return 0, errors.New("no user in context")
	}
	token := user.(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)
	sub := fmt.Sprint(claims["sub"])
	id, err := strconv.ParseUint(sub, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint(id), nil
}

// ==================== DB ====================

func initDB(dbUrl string) (*gorm.DB, error) {
	if dbUrl == "" {
		// default to sqlite file for quick local testing
		db, err := gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
		if err != nil {
			return nil, err
		}
		return db, nil
	}
	// Example DATABASE_URL for Postgres: "postgres://user:pass@host:5432/dbname"
	dsn := dbUrl
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	return db, nil
}

func migrate(db *gorm.DB) error {
	return db.AutoMigrate(&User{})
}

// ==================== Handlers ====================

func registerHandler(db *gorm.DB, cfg *Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var body RegisterRequest
		if err := c.BodyParser(&body); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
		}
		if err := validate.Struct(&body); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		}
		// check existing
		var existing User
		if err := db.Where("email = ?", strings.ToLower(body.Email)).First(&existing).Error; err == nil {
			return fiber.NewError(fiber.StatusBadRequest, "email already registered")
		}
		hashed, err := hashPassword(body.Password)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "failed to hash password")
		}
		user := User{
			Email:    strings.ToLower(body.Email),
			Password: hashed,
			Name:     body.Name,
		}
		if err := db.Create(&user).Error; err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "failed to create user")
		}
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
		})
	}
}

func loginHandler(db *gorm.DB, cfg *Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var body LoginRequest
		if err := c.BodyParser(&body); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
		}
		if err := validate.Struct(&body); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		}
		var user User
		if err := db.Where("email = ?", strings.ToLower(body.Email)).First(&user).Error; err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "invalid credentials")
		}
		if err := checkPasswordHash(user.Password, body.Password); err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "invalid credentials")
		}
		token, err := generateJWT(cfg.JWTSecret, user.ID, cfg.TokenExpiry)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "failed to generate token")
		}
		return c.JSON(fiber.Map{
			"access_token": token,
			"token_type":   "bearer",
			"expires_in":   int(cfg.TokenExpiry.Seconds()),
		})
	}
}

func profileHandler(db *gorm.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID, err := parseUserIDFromToken(c)
		if err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "invalid token")
		}
		var user User
		if err := db.First(&user, userID).Error; err != nil {
			return fiber.NewError(fiber.StatusNotFound, "user not found")
		}
		// Do not return password
		user.Password = ""
		return c.JSON(user)
	}
}

// ==================== Main ====================

func main() {
	// Load config
	cfg, err := loadConfigFromEnv()
	if err != nil {
		fmt.Println("Config error:", err)
		os.Exit(1)
	}

	// Init DB
	db, err := initDB(cfg.DBUrl)
	if err != nil {
		fmt.Println("DB init error:", err)
		os.Exit(1)
	}
	if err := migrate(db); err != nil {
		fmt.Println("DB migrate error:", err)
		os.Exit(1)
	}

	// Fiber app
	app := fiber.New(fiber.Config{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	})

	// Middlewares
	app.Use(recover.New())
	app.Use(requestid.New())
	app.Use(fiberlogger.New(fiberlogger.Config{
		Format:     "${time} ${status} ${latency} ${method} ${path} - ${ip}\n",
		TimeFormat: time.RFC3339,
		TimeZone:   "Local",
	}))
	app.Use(cors.New())

	// Rate limiter (simple per-IP)
	app.Use(limiter.New(limiter.Config{
		Max:        cfg.RateLimit,
		Expiration: cfg.RateWindow,
		KeyGenerator: func(c *fiber.Ctx) string {
			// prefer X-Real-IP/X-Forwarded-For if behind proxy
			if fwd := c.Get("X-Forwarded-For"); fwd != "" {
				return fwd
			}
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "rate limit exceeded",
			})
		},
	}))

	// Public routes
	api := app.Group("/api")
	auth := api.Group("/auth")
	auth.Post("/register", registerHandler(db, cfg))
	auth.Post("/login", loginHandler(db, cfg))

	// Protected routes (JWT)
	apiProtected := api.Group("/user")
	apiProtected.Use(jwtware.New(jwtware.Config{
		SigningKey:   []byte(cfg.JWTSecret),
		SigningMethod: "HS256",
		ContextKey:   "user", // stores *jwt.Token in locals under "user"
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		},
	}))
	apiProtected.Get("/profile", profileHandler(db))

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// Start server with graceful shutdown
	addr := fmt.Sprintf(":%d", cfg.Port)
	serverErrChan := make(chan error, 1)
	go func() {
		fmt.Printf("listening on %s (env=%s)\n", addr, cfg.Env)
		serverErrChan <- app.Listen(addr)
	}()

	// Wait for interrupt
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-quit:
		fmt.Println("signal:", sig)
	case err := <-serverErrChan:
		fmt.Println("server error:", err)
	}

	// Shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := app.Shutdown(); err != nil {
		fmt.Println("shutdown error:", err)
	}
	<-ctx.Done()
	fmt.Println("server stopped")
}
