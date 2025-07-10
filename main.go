package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	_ "github.com/lib/pq"
)

// ANSI color codes
const (
	RED    = "\033[0;31m"
	GREEN  = "\033[0;32m"
	YELLOW = "\033[1;33m"
	BLUE   = "\033[0;34m"
	PURPLE = "\033[0;35m"
	CYAN   = "\033[0;36m"
	WHITE  = "\033[1;37m"
	NC     = "\033[0m" // No Color
)

// AuthRequest represents the authentication request payload
type AuthRequest struct {
	StrategyName    string `json:"strategy_name"`
	RedirectOnStart bool   `json:"redirect_onstart"`
	ReturnTo        string `json:"return_to"`
	Email           string `json:"email"`
	CallbackURL     string `json:"callback_url"`
}

// AuthCallback represents the authentication callback payload
type AuthCallback struct {
	StrategyName string `json:"strategy_name"`
	Code         string `json:"code"`
	State        string `json:"state"`
}

// ListUsersRequest represents the request for listing users
type ListUsersRequest struct {
	PageSize   int `json:"page_size"`
	PageNumber int `json:"page_number"`
}

type AuthTokenResponse struct {
	AccessToken string `json:"accessToken"`
}

func listUsersWithToken(accessToken string) (string, error) {
	listReq := ListUsersRequest{
		PageSize:   10,
		PageNumber: 1,
	}

	jsonData, err := json.Marshal(listReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	req, err := http.NewRequest("POST", "http://localhost:8002/raystack.frontier.v1beta1.AdminService/ListAllUsers", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	printRespHeaders(resp)
	if err != nil {
		return "", fmt.Errorf("failed to make API call: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	return string(body), nil
}

// Logging functions
func logInfo(msg string) {
	fmt.Printf("%s%s%s\n", BLUE+"ℹ️  ", msg, NC)
}

func logSuccess(msg string) {
	fmt.Printf("%s%s%s\n", GREEN+"✅ ", msg, NC)
}

func logError(msg string) {
	fmt.Printf("%s%s%s\n", RED+"❌ ", msg, NC)
}

func logWarning(msg string) {
	fmt.Printf("%s%s%s\n", YELLOW+"⚠️  ", msg, NC)
}

func logStep(msg string) {
	fmt.Printf("%s%s%s\n", PURPLE+"🔄 ", msg, NC)
}

func logData(msg string) {
	fmt.Printf("%s%s%s\n", CYAN+"📋 ", msg, NC)
}

// extractState extracts the state from the JSON response
func extractState(jsonResponse string) (string, error) {
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(jsonResponse), &result); err != nil {
		// Fallback to regex if JSON parsing fails
		re := regexp.MustCompile(`"state":"([^"]*)"`)
		matches := re.FindStringSubmatch(jsonResponse)
		if len(matches) > 1 {
			return matches[1], nil
		}
		return "", fmt.Errorf("could not extract state from response")
	}

	if state, ok := result["state"].(string); ok {
		return state, nil
	}

	return "", fmt.Errorf("state not found in response")
}

// extractSidCookie extracts the sid cookie from response headers
func extractSidCookie(response *http.Response) (string, error) {
	for _, cookie := range response.Cookies() {
		if cookie.Name == "sid" {
			return cookie.Value, nil
		}
	}
	return "", fmt.Errorf("sid cookie not found in response")
}

// getNonceFromDB queries the database for the nonce
func getNonceFromDB(email string) (string, error) {
	db, err := sql.Open("postgres", "user=frontier host=localhost port=5432 sslmode=disable")
	if err != nil {
		return "", fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	var nonce string
	err = db.QueryRow("SELECT nonce FROM flows WHERE email=$1", email).Scan(&nonce)
	if err != nil {
		return "", fmt.Errorf("failed to query nonce: %w", err)
	}

	return strings.TrimSpace(nonce), nil
}

func printRespHeaders(resp *http.Response) {
	for name, headers := range resp.Header {
		// A header name can have multiple values (e.g., Set-Cookie)
		fmt.Printf("======headers=====")
		for _, hdr := range headers {
			fmt.Printf("%s: %s\n", name, hdr)
		}
	}
}

// makeAuthRequest makes the initial authentication request
func makeAuthRequest(email string) (string, error) {
	authReq := AuthRequest{
		StrategyName:    "mailotp",
		RedirectOnStart: false,
		ReturnTo:        "<string>",
		Email:           email,
		CallbackURL:     "localhost:8002",
	}

	jsonData, err := json.Marshal(authReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	resp, err := http.Post("http://localhost:8002/raystack.frontier.v1beta1.FrontierService/Authenticate",
		"application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to make authentication request: %w", err)
	}
	defer resp.Body.Close()
	for name, headers := range resp.Header {
		// A header name can have multiple values (e.g., Set-Cookie)
		fmt.Printf("======headers=====")
		for _, hdr := range headers {
			fmt.Printf("%s: %s\n", name, hdr)
		}
	}
	body, err := io.ReadAll(resp.Body)
	printRespHeaders(resp)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	return string(body), nil
}

// makeAuthCallback makes the authentication callback
func makeAuthCallback(nonce, state string) (*http.Response, error) {
	callback := AuthCallback{
		StrategyName: "mailotp",
		Code:         nonce,
		State:        state,
	}

	jsonData, err := json.Marshal(callback)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	resp, err := http.Post("http://localhost:8002/raystack.frontier.v1beta1.FrontierService/AuthCallback",
		"application/json", bytes.NewBuffer(jsonData))
	printRespHeaders(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to make authentication callback: %w", err)
	}

	return resp, nil
}

// listUsers makes the API call to list all users
func getAuthTokenWithCookie(sidCookie string) (*AuthTokenResponse, error) {
	req, err := http.NewRequest("POST", "http://localhost:8002/raystack.frontier.v1beta1.FrontierService/AuthToken", bytes.NewBuffer([]byte("{}")))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cookie", "sid="+sidCookie)

	client := &http.Client{}
	resp, err := client.Do(req)
	printRespHeaders(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to make API call: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var tokenResp AuthTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &tokenResp, nil
}

func listUsersWithCookie(sidCookie string) (string, error) {
	listReq := ListUsersRequest{
		PageSize:   10,
		PageNumber: 1,
	}

	jsonData, err := json.Marshal(listReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	req, err := http.NewRequest("POST", "http://localhost:8002/raystack.frontier.v1beta1.AdminService/ListAllUsers", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cookie", "sid="+sidCookie)

	client := &http.Client{}
	resp, err := client.Do(req)
	printRespHeaders(resp)
	if err != nil {
		return "", fmt.Errorf("failed to make API call: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	return string(body), nil
}

func main() {
	// Check if EMAIL environment variable is set
	email := os.Getenv("EMAIL")
	if email == "" {
		logError("EMAIL environment variable is not set")
		fmt.Printf("%sUsage: EMAIL=your@email.com go run main.go%s\n", WHITE, NC)
		os.Exit(1)
	}

	fmt.Printf("%s🚀 Starting authentication flow for email: %s%s%s\n", WHITE, YELLOW, email, NC)
	fmt.Printf("%s==================================================%s\n", WHITE, NC)

	// Step 1: Initial authentication request
	logStep("Step 1: Making initial authentication request...")
	logInfo("Endpoint: /raystack.frontier.v1beta1.FrontierService/Authenticate")

	authResponse, err := makeAuthRequest(email)
	if err != nil {
		logError(fmt.Sprintf("Failed to make authentication request: %v", err))
		os.Exit(1)
	}

	logData("Authentication response: " + authResponse)

	// Extract state from JSON response
	state, err := extractState(authResponse)
	if err != nil {
		logError("Could not extract state from response")
		logData("Response was: " + authResponse)
		os.Exit(1)
	}

	logSuccess("Extracted state: " + state)

	// Step 2: Query database for nonce
	logStep("Step 2: Querying database for nonce...")
	logInfo(fmt.Sprintf("Database: SELECT nonce FROM flows WHERE email='%s'", email))

	nonce, err := getNonceFromDB(email)
	if err != nil {
		logError(fmt.Sprintf("Could not retrieve nonce from database for email: %s - %v", email, err))
		os.Exit(1)
	}

	logSuccess("Retrieved nonce: " + nonce)

	// Step 3: Authentication callback
	logStep("Step 3: Making authentication callback...")
	logInfo("Endpoint: /raystack.frontier.v1beta1.FrontierService/AuthCallback")

	callbackResp, err := makeAuthCallback(nonce, state)
	if err != nil {
		logError(fmt.Sprintf("Failed to make authentication callback: %v", err))
		os.Exit(1)
	}
	defer callbackResp.Body.Close()

	logSuccess("Authentication callback completed successfully!")

	// Extract cookie from the response headers
	sidCookie, err := extractSidCookie(callbackResp)
	if err != nil {
		logError(fmt.Sprintf("Could not extract sid cookie from callback response: %v", err))
		os.Exit(1)
	}

	logSuccess("Extracted sid cookie: " + sidCookie)

	// Step 4: Get auth token using the cookie
	logStep("Step 4: Getting auth token...")
	logInfo("Endpoint: /raystack.frontier.v1beta1.FrontierService/AuthToken")

	tokenResp, err := getAuthTokenWithCookie(sidCookie)
	if err != nil {
		logError(fmt.Sprintf("Failed to get auth token: %v", err))
		os.Exit(1)
	}
	logSuccess("Retrieved auth token successfully!")

	// Step 5: Make API call to list all users using the bearer token
	logStep("Step 5: Making API call to list all users with bearer token...")
	logInfo("Endpoint: /raystack.frontier.v1beta1.AdminService/ListAllUsers")

	userResponseWithToken, err := listUsersWithToken(tokenResp.AccessToken)
	if err != nil {
		logError(fmt.Sprintf("Failed to list users with token: %v", err))
		os.Exit(1)
	}

	// Also try with cookie for comparison
	logStep("Step 6: Making API call to list all users with cookie...")
	logInfo("Endpoint: /raystack.frontier.v1beta1.AdminService/ListAllUsers")

	userResponseWithCookie, err := listUsersWithCookie(sidCookie)
	if err != nil {
		logError(fmt.Sprintf("Failed to list users with cookie: %v", err))
		os.Exit(1)
	}

	logSuccess("API calls completed successfully!")
	logData("Users response (with token): " + userResponseWithToken)
	logData("Users response (with cookie): " + userResponseWithCookie)
}
