package main

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

var (
	certRegexp    = regexp.MustCompile(`-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----`)
	privKeyRegexp = regexp.MustCompile(`-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----`)
)

// TrueNASConn wraps a websocket connection to provide logging.
type TrueNASConn struct {
	*websocket.Conn
}

func filterSecrets(data []byte) []byte {
	filtered := certRegexp.ReplaceAll(data, []byte(`#REDACTED#CERTIFICATE`))
	filtered = privKeyRegexp.ReplaceAll(filtered, []byte(`#REDACTED#PRIVATE KEY`))
	return filtered
}

func (c *TrueNASConn) WriteJSON(v interface{}) error {
	// Log request before sending
	b, err := json.Marshal(v)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to marshal request for logging")
	} else {
		if !strings.Contains(string(b), "auth.login_with_api_key") {
			log.Debug().RawJSON("request", filterSecrets(b)).Msg("Sending JSON message")
		}
	}

	return c.Conn.WriteJSON(v)
}

func (c *TrueNASConn) ReadJSON(v interface{}) error {
	err := c.Conn.ReadJSON(v)
	if err != nil {
		return err
	}

	// Log response after receiving
	b, err := json.Marshal(v)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to marshal response for logging")
	} else {
		log.Debug().RawJSON("response", filterSecrets(b)).Msg("Received JSON message")
	}

	return nil
}
