package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// JSONRPCRequest represents a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      string        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      string      `json:"id"`
	Result  interface{} `json:"result"`
	Error   interface{} `json:"error"`
}

func main() {
	// Define command-line flags for certificate and key paths
	certPath := flag.String("cert", "", "Path to the fullchain.pem certificate file")
	keyPath := flag.String("key", "", "Path to the privkey.pem file")
	flag.Parse()

	if *certPath == "" || *keyPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Get TrueNAS details from environment variables
	truenasURL := os.Getenv("TRUENAS_URL")
	truenasAPIKey := os.Getenv("TRUENAS_API_KEY")

	if truenasURL == "" || truenasAPIKey == "" {
		log.Fatal("TRUENAS_URL and TRUENAS_API_KEY environment variables must be set.")
	}

	fmt.Println("Configuration loaded:")
	fmt.Printf("  Certificate Path: %s\n", *certPath)
	fmt.Printf("  Private Key Path: %s\n", *keyPath)
	fmt.Printf("  TrueNAS URL: %s\n", truenasURL)

	// Read certificate and key files
	cert, err := os.ReadFile(*certPath)
	if err != nil {
		log.Fatalf("Failed to read certificate file: %v", err)
	}

	key, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatalf("Failed to read private key file: %v", err)
	}

	fmt.Println("Successfully read certificate and key files.")

	// Implement WebSocket connection and API call
	updateCertificate(truenasURL, truenasAPIKey, string(cert), string(key))
}

func updateCertificate(truenasURL, apiKey, cert, key string) {
	conn, err := newTrueNASClient(truenasURL, apiKey)
	if err != nil {
		log.Fatalf("Failed to connect to TrueNAS: %v", err)
	}
	defer conn.Close()

	certID, err := findCertificateID(conn, "go-certdist")
	if err != nil {
		log.Fatalf("Failed to query for certificate: %v", err)
	}

	if certID != -1 {
		if err := deleteCertificate(conn, certID); err != nil {
			log.Fatalf("Failed to delete old certificate: %v", err)
		}
		// waiting is a hack, but it works.
		log.Println("Waiting for 3 seconds for TrueNAS to settle...")
		time.Sleep(3 * time.Second)
	}

	if err := createCertificate(conn, "go-certdist", cert, key); err != nil {
		log.Fatalf("Failed to create new certificate: %v", err)
	}

	// After creation of the certificate an internal job is started inside of truenas to analyze the certificate
	// so we don't get the id right after creation. We need to wait a bit and then search for the certificate.
	log.Println("Waiting for 5 seconds for TrueNAS to process the new certificate...")
	time.Sleep(5 * time.Second)

	if err := setUICertificate(conn); err != nil {
		log.Fatalf("Failed to set UI certificate: %v", err)
	}

	log.Println("Certificate update process completed successfully.")
}

func newTrueNASClient(truenasURL, apiKey string) (*websocket.Conn, error) {
	// Construct WebSocket URL
	u, err := url.Parse(truenasURL)
	if err != nil {
		return nil, fmt.Errorf("invalid TrueNAS URL: %w", err)
	}

	wsScheme := "ws"
	if u.Scheme == "https" {
		wsScheme = "wss"
	}
	wsURL := fmt.Sprintf("%s://%s/api/current", wsScheme, u.Host)
	log.Println("WebSocket URL:", wsURL)

	// Configure dialer to skip TLS verification
	dialer := websocket.DefaultDialer
	dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	// Add Origin header
	header := http.Header{}
	header.Add("Origin", truenasURL)

	// Establish WebSocket connection
	conn, _, err := dialer.Dial(wsURL, header)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to TrueNAS WebSocket: %w", err)
	}

	// Authenticate
	loginReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      uuid.New().String(),
		Method:  "auth.login_with_api_key",
		Params:  []interface{}{apiKey},
	}

	if err := conn.WriteJSON(loginReq); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send authentication request: %w", err)
	}

	var loginResp JSONRPCResponse
	if err := conn.ReadJSON(&loginResp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read authentication response: %w", err)
	}

	if loginResp.Error != nil {
		conn.Close()
		return nil, fmt.Errorf("authentication failed: %v", loginResp.Error)
	}

	log.Println("Successfully connected and authenticated with TrueNAS.")
	return conn, nil
}

func findCertificateID(conn *websocket.Conn, name string) (int64, error) {
	queryReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      uuid.New().String(),
		Method:  "certificate.query",
		Params:  []interface{}{[]interface{}{[]string{"name", "=", name}}},
	}

	if err := conn.WriteJSON(queryReq); err != nil {
		return -1, fmt.Errorf("failed to send certificate query request: %w", err)
	}

	var queryResp JSONRPCResponse
	if err := conn.ReadJSON(&queryResp); err != nil {
		return -1, fmt.Errorf("failed to read certificate query response: %w", err)
	}

	if queryResp.Error != nil {
		return -1, fmt.Errorf("certificate query failed: %v", queryResp.Error)
	}

	results, ok := queryResp.Result.([]interface{})
	if !ok {
		return -1, fmt.Errorf("unexpected format for certificate query result")
	}

	if len(results) == 0 {
		log.Printf("No certificate named '%s' found.", name)
		return -1, nil // Not found is not an error
	}

	certData, ok := results[0].(map[string]interface{})
	if !ok {
		return -1, fmt.Errorf("unexpected format for certificate data")
	}

	certID, ok := certData["id"].(float64)
	if !ok {
		return -1, fmt.Errorf("could not find ID for certificate '%s'", name)
	}

	log.Printf("Found existing certificate '%s' with ID: %d.", name, int64(certID))
	return int64(certID), nil
}

func deleteCertificate(conn *websocket.Conn, id int64) error {
	log.Printf("Deleting certificate with ID: %d...", id)
	deleteReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      uuid.New().String(),
		Method:  "certificate.delete",
		Params:  []interface{}{id},
	}

	if err := conn.WriteJSON(deleteReq); err != nil {
		return fmt.Errorf("failed to send certificate delete request: %w", err)
	}

	var deleteResp JSONRPCResponse
	if err := conn.ReadJSON(&deleteResp); err != nil {
		return fmt.Errorf("failed to read certificate delete response: %w", err)
	}

	if deleteResp.Error != nil {
		return fmt.Errorf("certificate deletion failed: %v", deleteResp.Error)
	}

	log.Println("Successfully deleted old certificate.")
	return nil
}

func createCertificate(conn *websocket.Conn, name, cert, key string) error {
	log.Printf("Creating new certificate '%s'...", name)
	createReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      uuid.New().String(),
		Method:  "certificate.create",
		Params: []interface{}{map[string]interface{}{
			"name":        name,
			"create_type": "CERTIFICATE_CREATE_IMPORTED",
			"certificate": cert,
			"privatekey":  key,
			"passphrase":  "",
		}},
	}

	if err := conn.WriteJSON(createReq); err != nil {
		return fmt.Errorf("failed to send certificate create request: %w", err)
	}

	var createResp JSONRPCResponse
	if err := conn.ReadJSON(&createResp); err != nil {
		return fmt.Errorf("failed to read certificate create response: %w", err)
	}
	logJsonResponse(createResp)

	if createResp.Error != nil {
		return fmt.Errorf("certificate creation failed: %v", createResp.Error)
	}

	log.Println("Successfully created certificate on TrueNAS.")
	return nil
}

func logJsonResponse(createResp JSONRPCResponse) {
	jsonResp, err := json.Marshal(createResp)
	if err != nil {
		log.Printf("Error marshaling response to JSON: %v. Raw response: %+v", err, createResp)
	} else {
		log.Println("TrueNAS response:", string(jsonResp))
	}
}

func setUICertificate(conn *websocket.Conn) error {
	log.Println("Searching for UI certificate 'go-certdist'...")
	certID, err := findCertificateID(conn, "go-certdist")
	if err != nil {
		return fmt.Errorf("failed to find certificate 'go-certdist': %w", err)
	}
	if certID == -1 {
		return fmt.Errorf("certificate 'go-certdist' not found after creation")
	}

	log.Printf("Setting UI certificate to new certificate with ID: %d...", certID)
	updateReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      uuid.New().String(),
		Method:  "system.general.update",
		Params: []interface{}{map[string]interface{}{
			"ui_certificate": certID,
		}},
	}

	if err := conn.WriteJSON(updateReq); err != nil {
		return fmt.Errorf("failed to send UI certificate update request: %w", err)
	}

	var updateResp JSONRPCResponse
	if err := conn.ReadJSON(&updateResp); err != nil {
		return fmt.Errorf("failed to read UI certificate update response: %w", err)
	}

	if updateResp.Error != nil {
		return fmt.Errorf("UI certificate update failed: %v", updateResp.Error)
	}

	log.Println("Successfully updated UI certificate.")
	return nil
}
