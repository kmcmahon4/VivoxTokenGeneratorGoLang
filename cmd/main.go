package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"go.uber.org/zap"
)

const (
	emptyString = ""
	TokenHeader = "e30"
	ActionJoin  = "join"
	ActionLogin = "login"
)

type TokenGenerationArgs struct {
	Issuer        string
	Domain        string
	TokenDuration int
	UserID        string
	ChannelId     string
	Key           string
	Action        string
}

type VivoxLoginJwt struct {
	Issuer        string `json:"iss"`
	Expiration    int    `json:"exp"`
	VivoxAction   string `json:"vxa"`
	VivoxUniqueId int64  `json:"vxi"`
	From          string `json:"f"`
}

type VivoxJoinJwt struct {
	Issuer        string `json:"iss"`
	Expiration    int    `json:"exp"`
	VivoxAction   string `json:"vxa"`
	VivoxUniqueId int64  `json:"vxi"`
	From          string `json:"f"`
	To            string `json:"t"`
}

var logger, _ = zap.NewProduction()

func main() {
	err := godotenv.Load("config.env")
	if err != nil {
		log.Fatal("error loading config file")
	}

	// get args
	issuer := os.Getenv("VIVOX_ISSUER")
	domain := os.Getenv("VIVOX_DOMAIN")
	tokenDuration, _ := strconv.Atoi(os.Getenv("TOKEN_DURATION_SECONDS"))
	userId := os.Getenv("VIVOX_USER_ID")
	channelId := os.Getenv("VIVOX_CHANNEL_ID")
	key := os.Getenv("VIVOX_KEY")
	action := os.Getenv("VIVOX_ACTION")

	args := &TokenGenerationArgs{
		Issuer:        issuer,
		Domain:        domain,
		TokenDuration: tokenDuration,
		UserID:        userId,
		ChannelId:     channelId,
		Key:           key,
		Action:        action,
	}

	tokenGenerator := NewTokenGenerator()

	// just log it to console for now
	// auto copy to clipboard?
	logger.Info(tokenGenerator.GenerateToken(*args))
}

type TokenGenerator interface {
	GenerateToken(args TokenGenerationArgs) string
	base64URLEncode(bytes []byte) string
	sha256Hash(secret string, message string) string
	generateUniquId() int64
	generatePlayerSIP(issuer string, domain string, playerId string) string
	generateChannelSIP(issuer string, domain string, channelName string) string
	generateExpiration(durationInSeconds int) int
}

type tokenGenerator struct {
}

func NewTokenGenerator() TokenGenerator {
	return &tokenGenerator{}
}

var _ TokenGenerator = (*tokenGenerator)(nil)

func (t *tokenGenerator) GenerateToken(args TokenGenerationArgs) string {

	err := args.validate()
	if err != nil {
		logger.Fatal("invalid arguments", zap.Error(err))
		return emptyString
	}

	tokenSegments := make([]string, 0, 3)

	tokenSegments = append(tokenSegments, TokenHeader)

	var jsonToConvert any

	// construct JSON object to encode
	if args.Action == ActionLogin {
		jsonToConvert = &VivoxLoginJwt{
			Issuer:        args.Issuer,
			Expiration:    t.generateExpiration(args.TokenDuration),
			VivoxAction:   args.Action,
			VivoxUniqueId: t.generateUniquId(),
			From:          t.generatePlayerSIP(args.Issuer, args.Domain, args.UserID),
		}
	}

	if args.Action == ActionJoin {
		jsonToConvert = &VivoxJoinJwt{
			Issuer:        args.Issuer,
			Expiration:    t.generateExpiration(args.TokenDuration),
			VivoxAction:   args.Action,
			VivoxUniqueId: t.generateUniquId(),
			From:          t.generatePlayerSIP(args.Issuer, args.Domain, args.UserID),
			To:            t.generateChannelSIP(args.Issuer, args.Domain, args.ChannelId),
		}
	}

	bytes, err := json.Marshal(jsonToConvert)
	if err != nil {
		return emptyString
	}

	encodedPayload := t.base64URLEncode(bytes)
	tokenSegments = append(tokenSegments, encodedPayload)

	toSign := strings.Join(tokenSegments, ".")

	signature := t.sha256Hash(args.Key, toSign)
	tokenSegments = append(tokenSegments, signature)

	token := strings.Join(tokenSegments, ".")

	return token
}

func (t *tokenGenerator) sha256Hash(secret string, message string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))

	return t.base64URLEncode(h.Sum(nil))
}

func (t *tokenGenerator) base64URLEncode(bytes []byte) string {
	encodedString := base64.StdEncoding.EncodeToString(bytes)

	// Remove invalid char at the end
	encodedString = strings.TrimRight(encodedString, "=")

	// URL safe chars
	encodedString = strings.ReplaceAll(encodedString, "+", "-")
	encodedString = strings.ReplaceAll(encodedString, "/", "_")

	return encodedString
}

func (t *tokenGenerator) generateUniquId() int64 {
	return time.Now().UnixNano()
}

func (t *tokenGenerator) generatePlayerSIP(issuer string, domain string, playerId string) string {
	return fmt.Sprintf("sip:.%s.%s.@%s", issuer, playerId, domain)
}

func (t *tokenGenerator) generateChannelSIP(issuer string, domain string, channelName string) string {
	if channelName == emptyString {
		return emptyString
	}

	return fmt.Sprintf("sip:confctl-g-%s.%s@%s", issuer, channelName, domain)
}

func (t *tokenGenerator) generateExpiration(durationInSeconds int) int {
	return int(time.Now().Add((time.Second * time.Duration(durationInSeconds))).Unix())
}

func (t *TokenGenerationArgs) validate() error {
	if t.Key == emptyString {
		return errors.New("key cannot be empty")
	}
	if t.Issuer == emptyString {
		return errors.New("issuer cannot be empty")
	}
	if t.Domain == emptyString {
		return errors.New("domain cannot be empty")
	}
	if t.TokenDuration <= 0 {
		return errors.New("TokenDuration cannot be 0 or negative")
	}
	return nil
}
