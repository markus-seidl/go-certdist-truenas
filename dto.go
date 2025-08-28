package main

import "encoding/json"

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
