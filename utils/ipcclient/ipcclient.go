// Package ipcclient provides a thin JSON client for talking to the daemon's
// Unix domain socket IPC interface.
package ipcclient

import (
	"encoding/json"
	"fmt"
	"net"

	"p2pvpn/utils/daemon"
)

// Client wraps a connection to the daemon IPC socket.
type Client struct {
	socketPath string
}

// New returns a Client pointed at socketPath.
func New(socketPath string) *Client {
	if socketPath == "" {
		socketPath = daemon.DefaultSocketPath
	}
	return &Client{socketPath: socketPath}
}

// Call sends a command and returns the parsed response.
func (c *Client) Call(command string, args interface{}) (*daemon.IPCResponse, error) {
	conn, err := net.Dial("unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to daemon at %s (is it running?): %w", c.socketPath, err)
	}
	defer conn.Close()

	req := daemon.IPCRequest{Command: command}
	if args != nil {
		raw, err := json.Marshal(args)
		if err != nil {
			return nil, fmt.Errorf("marshalling args: %w", err)
		}
		req.Args = raw
	}

	enc := json.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}

	var resp daemon.IPCResponse
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return &resp, nil
}

// MustCall calls the daemon and returns the raw JSON data, or prints the error
// and returns nil.
func (c *Client) MustCall(command string, args interface{}) json.RawMessage {
	resp, err := c.Call(command, args)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return nil
	}
	if !resp.OK {
		fmt.Printf("error: %s\n", resp.Error)
		return nil
	}
	return resp.Data
}
