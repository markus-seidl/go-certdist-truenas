package main

import (
	"context"
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
	Msg     string      `json:"msg"`
}

type WebsocketMessage struct {
	JSONRPC string          `json:"jsonrpc,omitempty"`
	ID      string          `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   interface{}     `json:"error,omitempty"`
	Msg     string          `json:"msg,omitempty"` // For non-jsonrpc messages like 'changed'
}

type CollectionUpdateParams struct {
	Msg        string     `json:"msg"`
	Collection string     `json:"collection"`
	Fields     *JobFields `json:"fields,omitempty"`
}

type JobFields struct {
	ID         int64           `json:"id"`
	Method     string          `json:"method"`
	MessageIDs []string        `json:"message_ids,omitempty"`
	Progress   JobProgress     `json:"progress"`
	State      string          `json:"state"`
	Result     json.RawMessage `json:"result"`
	Error      interface{}     `json:"error"`
}

type JobProgress struct {
	Percent     float64 `json:"percent"`
	Description string  `json:"description"`
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
		if err := deleteCertificate(conn, "go-certdist", certID); err != nil {
			log.Fatalf("Failed to delete old certificate: %v", err)
		}
	}

	if err := createCertificate(conn, "go-certdist", cert, key); err != nil {
		log.Fatalf("Failed to create new certificate: %v", err)
	}

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

	// Subscribe to job updates
	subReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      uuid.New().String(),
		Method:  "core.subscribe",
		Params:  []interface{}{"core.get_jobs"},
	}

	if err := conn.WriteJSON(subReq); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send subscription request: %w", err)
	}

	var subResp JSONRPCResponse
	if err := conn.ReadJSON(&subResp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read subscription response: %w", err)
	}
	logJsonResponse(subResp)
	//if subResp.Msg != "ready" {
	conn.Close()
	//return nil, fmt.Errorf("failed to subscribe to jobs, server sent: %s", subResp.Msg)
	//}
	log.Println("Successfully subscribed to core.get_jobs.")

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

	certIDFloat, ok := certData["id"].(float64)
	if !ok {
		return -1, fmt.Errorf("could not find ID for certificate '%s'", name)
	}

	log.Printf("Found existing certificate '%s' with ID: %d.", name, int64(certIDFloat))
	return int64(certIDFloat), nil
}

func callAndWait(conn *websocket.Conn, req JSONRPCRequest) (json.RawMessage, error) {
	if err := conn.WriteJSON(req); err != nil {
		return nil, fmt.Errorf("failed to send request '%s': %w", req.Method, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var jobID int64 = -1
	var jobState string

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timed out waiting for response for method '%s' (Job ID: %d)", req.Method, jobID)
		default:
			var msg WebsocketMessage
			if err := conn.ReadJSON(&msg); err != nil {
				return nil, fmt.Errorf("error reading websocket message: %w", err)
			}

			// Handle final RPC result
			if msg.ID == req.ID {
				if msg.Error != nil {
					return nil, fmt.Errorf("received final error for method '%s': %v", req.Method, msg.Error)
				}
				// We have the final result, but we should wait for the job to be 'SUCCESS' just in case.
				if jobState == "SUCCESS" {
					log.Printf("Received final result for job %d.", jobID)
					return msg.Result, nil
				}
				// If we get here, the final result arrived before the final job state update. We'll wait for it.
			}

			// Handle job notifications
			if msg.Method == "collection_update" {
				var update CollectionUpdateParams
				if err := json.Unmarshal(msg.Params, &update); err != nil {
					log.Printf("Failed to unmarshal collection_update params: %v", err)
					continue
				}

				if update.Collection != "core.get_jobs" || update.Fields == nil {
					continue
				}

				// Check if this job belongs to our request
				isOurJob := false
				if jobID != -1 && update.Fields.ID == jobID {
					isOurJob = true
				} else {
					for _, msgID := range update.Fields.MessageIDs {
						if msgID == req.ID {
							isOurJob = true
							jobID = update.Fields.ID // Found our job ID
							break
						}
					}
				}

				if !isOurJob {
					continue
				}

				jobState = update.Fields.State
				log.Printf("Job %d (%s): %d%% - %s [%s]", jobID, update.Fields.Method, int(update.Fields.Progress.Percent), update.Fields.Progress.Description, jobState)

				if jobState == "FAILED" {
					return nil, fmt.Errorf("job %d for method '%s' failed: %v", jobID, req.Method, update.Fields.Error)
				}
			}
		}
	}
}

func deleteCertificate(conn *websocket.Conn, name string, certID int64) error {
	log.Printf("Deleting existing certificate '%s' (ID: %d)...", name, certID)
	deleteReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      uuid.New().String(),
		Method:  "certificate.delete",
		Params:  []interface{}{certID},
	}

	_, err := callAndWait(conn, deleteReq)
	if err != nil {
		return fmt.Errorf("certificate deletion failed: %w", err)
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

	_, err := callAndWait(conn, createReq)
	if err != nil {
		return fmt.Errorf("certificate creation failed: %w", err)
	}

	log.Println("Successfully created certificate on TrueNAS.")
	return nil
}

func logJsonResponse(resp interface{}) {
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		log.Printf("Error marshaling response to JSON: %v. Raw response: %+v", err, resp)
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

	_, err = callAndWait(conn, updateReq)
	if err != nil {
		return fmt.Errorf("UI certificate update failed: %w", err)
	}

	log.Println("Successfully updated UI certificate.")
	return nil
}
