package main

import (
	"encoding/json"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

type TrueNASConn struct {
	*websocket.Conn
}

func (c *TrueNASConn) WriteJSON(v interface{}) error {
	// Log request before sending
	b, err := json.Marshal(v)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to marshal request for logging")
	} else {
		log.Debug().RawJSON("request", b).Msg("Sending JSON message")
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
		log.Debug().RawJSON("response", b).Msg("Received JSON message")
	}

	return nil
}
