package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

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

type WebsocketMessage struct {
	JSONRPC string          `json:"jsonrpc,omitempty"`
	ID      string          `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   interface{}     `json:"error,omitempty"`
}

type CollectionUpdateParams struct {
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
	// Setup zerolog
	InitLogger()

	// Define command-line flags for certificate and key paths
	certPath := flag.String("cert", "", "Path to the fullchain.pem certificate file")
	keyPath := flag.String("key", "", "Path to the privkey.pem file")
	flag.Parse()

	if *certPath == "" || *keyPath == "" {
		log.Fatal().Msg("TRUENAS_URL and TRUENAS_API_KEY environment variables must be set.")
	}

	log.Info().
		Str("certPath", *certPath).
		Str("keyPath", *keyPath).
		Msg("Configuration loaded")

	// Get TrueNAS details from environment variables
	truenasURL := os.Getenv("TRUENAS_URL")
	truenasAPIKey := os.Getenv("TRUENAS_API_KEY")

	if truenasURL == "" || truenasAPIKey == "" {
		log.Fatal().Msg("TRUENAS_URL and TRUENAS_API_KEY environment variables must be set.")
	}

	log.Info().
		Str("truenasURL", truenasURL).
		Msg("TrueNAS URL loaded")

	// Read certificate and key files
	cert, err := os.ReadFile(*certPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to read certificate file")
	}

	key, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to read private key file")
	}

	log.Info().Msg("Successfully read certificate and key files.")

	// Implement WebSocket connection and API call
	updateCertificate(truenasURL, truenasAPIKey, string(cert), string(key))
}

func InitLogger() {
	consoleWriter := zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
		w.Out = os.Stdout
		w.TimeFormat = "2006-01-02 15:04:05"
		w.FormatLevel = func(i interface{}) string {
			s := fmt.Sprintf("%s", i)
			if len(s) > 4 {
				s = s[:4]
			}
			return s
		}
	})

	log.Logger = log.Output(consoleWriter).With().Caller().Logger()
	//zerolog.SetGlobalLevel(zerolog.InfoLevel)
}

func updateCertificate(truenasURL, apiKey, cert, key string) {
	conn, err := newTrueNASClient(truenasURL, apiKey)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to TrueNAS")
	}
	defer conn.Close()

	// Check current UI certificate
	currentCertID, err := getCurrentUICertificateID(conn)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get current UI certificate")
	}

	// Find our certificate if it exists
	certID, err := findCertificateID(conn, "go-certdist")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to query for certificate")
	}

	// If the current UI certificate is our cert, switch to default first
	if certID != -1 && currentCertID == certID {
		log.Info().Msg("Current UI certificate is the one we want to update, switching to default certificate...")
		if err := setUICertificate(conn, 1); err != nil { // 1 is typically the default TrueNAS certificate
			log.Fatal().Err(err).Msg("Failed to switch to default certificate")
		}
	}

	// Delete the old certificate if it exists
	if certID != -1 {
		if err := deleteCertificate(conn, "go-certdist", certID); err != nil {
			log.Fatal().Err(err).Msg("Failed to delete old certificate")
		}
	}

	// Create the new certificate
	if err := createCertificate(conn, "go-certdist", cert, key); err != nil {
		log.Fatal().Err(err).Msg("Failed to create new certificate")
	}

	// Get the new certificate ID
	newCertID, err := findCertificateID(conn, "go-certdist")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to find new certificate")
	}

	// Set the UI to use the new certificate
	if err := setUICertificate(conn, newCertID); err != nil {
		log.Fatal().Err(err).Msg("Failed to set UI certificate")
	}

	log.Info().Msg("Certificate update process completed successfully.")

	// Restart the UI to apply the new certificate
	if err := restartUI(conn); err != nil {
		log.Fatal().Err(err).Msg("Failed to restart TrueNAS UI")
	}
}

// getCurrentUICertificateID returns the ID of the current UI certificate
func getCurrentUICertificateID(conn *TrueNASConn) (int64, error) {
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      uuid.New().String(),
		Method:  "system.general.config",
		Params:  []interface{}{},
	}

	result, err := callAndWait(conn, req)
	if err != nil {
		return -1, fmt.Errorf("failed to get system general config: %w", err)
	}

	var config struct {
		UICertificate struct {
			ID int64 `json:"id"`
		} `json:"ui_certificate"`
	}
	if err := json.Unmarshal(result, &config); err != nil {
		return -1, fmt.Errorf("failed to unmarshal system config: %w", err)
	}

	return config.UICertificate.ID, nil
}

func newTrueNASClient(truenasURL, apiKey string) (*TrueNASConn, error) {
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
	log.Info().Str("url", wsURL).Msg("Connecting to WebSocket")

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
	// Wrap the connection
	tnc := &TrueNASConn{Conn: conn}

	// Authenticate
	loginReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      uuid.New().String(),
		Method:  "auth.login_with_api_key",
		Params:  []interface{}{apiKey},
	}

	if err := tnc.WriteJSON(loginReq); err != nil {
		tnc.Close()
		return nil, fmt.Errorf("failed to send authentication request: %w", err)
	}

	var loginResp JSONRPCResponse
	if err := tnc.ReadJSON(&loginResp); err != nil {
		tnc.Close()
		return nil, fmt.Errorf("failed to read authentication response: %w", err)
	}

	if loginResp.Error != nil {
		tnc.Close()
		return nil, fmt.Errorf("authentication failed: %v", loginResp.Error)
	}

	log.Info().Msg("Successfully connected and authenticated with TrueNAS.")
	// No subscription needed, we'll use direct job status queries

	return tnc, nil
}

func findCertificateID(conn *TrueNASConn, name string) (int64, error) {
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
		log.Info().Str("name", name).Msg("No certificate with given name found.")
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

	log.Info().Str("name", name).Int64("id", int64(certIDFloat)).Msg("Found existing certificate")
	return int64(certIDFloat), nil
}

// getJobStatus queries the status of a specific job
func getJobStatus(conn *TrueNASConn, jobID int64) (*JobFields, error) {
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
func waitForJobCompletion(conn *TrueNASConn, jobID int64, timeout time.Duration) (*JobFields, error) {
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

			log.Debug().
				Int64("jobID", job.ID).
				Str("method", job.Method).
				Str("state", job.State).
				Int("progress", int(job.Progress.Percent)).
				Str("description", job.Progress.Description).
				Msg("Job status update")
		}
	}
}

func callAndWait(conn *TrueNASConn, req JSONRPCRequest) (json.RawMessage, error) {
	if err := conn.WriteJSON(req); err != nil {
		return nil, fmt.Errorf("failed to send request '%s': %w", req.Method, err)
	}

	reqId := req.ID

	// For the initial response
	var resp JSONRPCResponse
	if err := conn.ReadJSON(&resp); err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}
	log.Debug().Str("reqId", reqId).Msg("Initial response received")

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

func deleteCertificate(conn *TrueNASConn, name string, certID int64) error {
	log.Info().Str("name", name).Int64("id", certID).Msg("Deleting certificate")
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

	log.Info().Msg("Successfully deleted old certificate.")
	return nil
}

func createCertificate(conn *TrueNASConn, name, cert, key string) error {
	log.Info().Str("name", name).Msg("Creating new certificate")
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

	log.Info().Msg("Successfully created certificate on TrueNAS.")
	return nil
}

// setUICertificate sets the UI to use the specified certificate ID
func setUICertificate(conn *TrueNASConn, certID int64) error {
	log.Info().Int64("certID", certID).Msg("Setting UI certificate")
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

	log.Info().Msg("Successfully updated UI certificate.")
	return nil
}

// restartUI triggers a restart of the TrueNAS web UI.
func restartUI(conn *TrueNASConn) error {
	log.Info().Msg("Requesting TrueNAS UI restart...")
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      uuid.New().String(),
		Method:  "system.general.ui_restart",
		Params:  []interface{}{},
	}

	_, err := callAndWait(conn, req)
	if err != nil {
		return fmt.Errorf("failed to restart UI: %w", err)
	}

	log.Info().Msg("UI restart command issued successfully. It may take a minute for the UI to be available again.")
	return nil
}
