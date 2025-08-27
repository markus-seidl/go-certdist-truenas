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
	Exception  string          `json:"exception"`
	Abortable  bool            `json:"abortable"`
	Timeout    int             `json:"timeout"`
	Username   string          `json:"username"`
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

	// Check current UI certificate
	currentCertID, err := getCurrentUICertificateID(conn)
	if err != nil {
		log.Fatalf("Failed to get current UI certificate: %v", err)
	}

	// Find our certificate if it exists
	certID, err := findCertificateID(conn, "go-certdist")
	if err != nil {
		log.Fatalf("Failed to query for certificate: %v", err)
	}

	// If the current UI certificate is our cert, switch to default first
	if certID != -1 && currentCertID == certID {
		log.Println("Current UI certificate is the one we want to update, switching to default certificate...")
		if err := setUICertificate(conn, 1); err != nil { // 1 is typically the default TrueNAS certificate
			log.Fatalf("Failed to switch to default certificate: %v", err)
		}
	}

	// Delete the old certificate if it exists
	if certID != -1 {
		if err := deleteCertificate(conn, "go-certdist", certID); err != nil {
			log.Fatalf("Failed to delete old certificate: %v", err)
		}
	}

	// Create the new certificate
	if err := createCertificate(conn, "go-certdist", cert, key); err != nil {
		log.Fatalf("Failed to create new certificate: %v", err)
	}

	// Get the new certificate ID
	newCertID, err := findCertificateID(conn, "go-certdist")
	if err != nil {
		log.Fatalf("Failed to find new certificate: %v", err)
	}

	// Set the UI to use the new certificate
	if err := setUICertificate(conn, newCertID); err != nil {
		log.Fatalf("Failed to set UI certificate: %v", err)
	}

	log.Println("Certificate update process completed successfully.")
}

// getCurrentUICertificateID returns the ID of the current UI certificate
func getCurrentUICertificateID(conn *websocket.Conn) (int64, error) {
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      uuid.New().String(),
		Method:  "system.general.config",
	}

	result, err := callAndWait(conn, req)
	if err != nil {
		return -1, fmt.Errorf("failed to get system general config: %w", err)
	}

	var config struct {
		UICertificateID int64 `json:"ui_certificate"`
	}
	if err := json.Unmarshal(result, &config); err != nil {
		return -1, fmt.Errorf("failed to unmarshal system config: %w", err)
	}

	return config.UICertificateID, nil
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
	// No subscription needed, we'll use direct job status queries

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

// getJobStatus queries the status of a specific job
func getJobStatus(conn *websocket.Conn, jobID int64) (*JobFields, error) {
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      uuid.New().String(),
		Method:  "core.get_jobs",
		Params: []interface{}{
			[]interface{}{[]interface{}{"id", "=", jobID}},
		},
	}

	if err := conn.WriteJSON(req); err != nil {
		return nil, fmt.Errorf("failed to send job status request: %w", err)
	}

	var resp JSONRPCResponse
	if err := conn.ReadJSON(&resp); err != nil {
		return nil, fmt.Errorf("failed to read job status response: %w", err)
	}
	logJsonResponse(resp)

	if resp.Error != nil {
		return nil, fmt.Errorf("error getting job status: %v", resp.Error)
	}

	// Handle different response formats
	var job JobFields
	switch v := resp.Result.(type) {
	case []interface{}:
		if len(v) == 0 {
			return nil, fmt.Errorf("job %d not found", jobID)
		}
		// Convert the first item to JSON and then unmarshal to JobFields
		jobData, err := json.Marshal(v[0])
		if err != nil {
			return nil, fmt.Errorf("failed to marshal job data: %w", err)
		}
		if err := json.Unmarshal(jobData, &job); err != nil {
			return nil, fmt.Errorf("failed to unmarshal job data: %w", err)
		}
	case map[string]interface{}:
		// Directly unmarshal if it's a single job object
		jobData, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal job data: %w", err)
		}
		if err := json.Unmarshal(jobData, &job); err != nil {
			return nil, fmt.Errorf("failed to unmarshal job data: %w", err)
		}
	default:
		return nil, fmt.Errorf("unexpected job data format: %T", v)
	}

	return &job, nil
}

// waitForJobCompletion waits for a job to complete
func waitForJobCompletion(conn *websocket.Conn, jobID int64, timeout time.Duration) (*JobFields, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timed out waiting for job %d to complete", jobID)
		case <-ticker.C:
			job, err := getJobStatus(conn, jobID)
			if err != nil {
				return nil, err
			}

			switch job.State {
			case "SUCCESS":
				return job, nil
			case "FAILED":
				errorMsg := "unknown error"
				if job.Error != nil {
					errorMsg = fmt.Sprintf("%v", job.Error)
				} else if job.Exception != "" {
					errorMsg = job.Exception
				}
				return nil, fmt.Errorf("job %d failed: %s", jobID, errorMsg)
			case "ABORTED":
				return nil, fmt.Errorf("job %d was aborted", jobID)
			}

			log.Printf("Job %d (%s) status: %s - %d%% - %s",
				job.ID, job.Method, job.State,
				int(job.Progress.Percent),
				job.Progress.Description)
		}
	}
}

func callAndWait(conn *websocket.Conn, req JSONRPCRequest) (json.RawMessage, error) {
	if err := conn.WriteJSON(req); err != nil {
		return nil, fmt.Errorf("failed to send request '%s': %w", req.Method, err)
	}

	reqId := req.ID

	// For the initial response
	var resp JSONRPCResponse
	if err := conn.ReadJSON(&resp); err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}
	fmt.Println("ReqId", reqId)
	logJsonResponse(resp)

	// If the response has an error, return it
	if resp.Error != nil {
		return nil, fmt.Errorf("error in response: %v", resp.Error)
	}

	// If the response contains a job ID, wait for it to complete
	var jobID int64
	if id, ok := resp.Result.(float64); ok {
		jobID = int64(id)
	}

	if jobID > 0 {
		job, err := waitForJobCompletion(conn, jobID, 5*time.Minute)
		if err != nil {
			return nil, fmt.Errorf("error waiting for job %d: %w", jobID, err)
		}
		return job.Result, nil
	}

	// If no job ID, return the raw result
	result, err := json.Marshal(resp.Result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %w", err)
	}
	return result, nil
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

// setUICertificate sets the UI to use the specified certificate ID
func setUICertificate(conn *websocket.Conn, certID int64) error {
	log.Printf("Setting UI certificate to use certificate with ID: %d...", certID)
	updateReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      uuid.New().String(),
		Method:  "system.general.update",
		Params: []interface{}{map[string]interface{}{
			"ui_certificate": certID,
		}},
	}

	_, err := callAndWait(conn, updateReq)
	if err != nil {
		return fmt.Errorf("UI certificate update failed: %w", err)
	}

	log.Println("Successfully updated UI certificate.")
	return nil
}
