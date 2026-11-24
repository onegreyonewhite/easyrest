package pingpong

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// PongPath is the restapi view path segment for the pong handler.
const PongPath = "/restapi/v1/game/pong/"

// RunPing GETs pingURL until the body is pong, then logs each success until ctx ends.
func RunPing(ctx context.Context, pingURL string, logf func(string, ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	client := &http.Client{Timeout: 2 * time.Second}
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pingURL, nil)
		if err != nil {
			return fmt.Errorf("ping request: %w", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			timer.Reset(200 * time.Millisecond)
			continue
		}
		body, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("ping read body: %w", readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("ping close body: %w", closeErr)
		}
		if resp.StatusCode != http.StatusOK {
			timer.Reset(200 * time.Millisecond)
			continue
		}
		if string(body) != "pong" {
			return fmt.Errorf("ping body: got %q", string(body))
		}
		logf("ping: pong")
		timer.Reset(2 * time.Second)
	}
}

// PingOnce GETs pingURL once and returns the response body.
func PingOnce(ctx context.Context, pingURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pingURL, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	return string(body), nil
}

// ErrPingTimeout is returned when the pong view does not answer in time.
var ErrPingTimeout = errors.New("ping: pong not received in time")