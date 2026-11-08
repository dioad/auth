package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func doRequestAndUnmarshallJSON[T any](ctx context.Context, doer HTTPDoer, req *http.Request) (*T, error) {
	ctxReq := req.WithContext(ctx)

	if doer == nil {
		doer = defaultHTTPClient()
	}
	resp, err := doer.Do(ctxReq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(" request failed with status: %v", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var data T
	err = json.Unmarshal(body, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

func doPostWithBasicAuth[T any](ctx context.Context, doer HTTPDoer, url string, data url.Values, username, password string) (*T, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(username, password)

	return doRequestAndUnmarshallJSON[T](ctx, doer, req)
}

func doPost[T any](ctx context.Context, doer HTTPDoer, url string, data url.Values) (*T, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return doRequestAndUnmarshallJSON[T](ctx, doer, req)
}

// doPostNoContent posts data as a form and accepts any 2xx response,
// discarding its body, for endpoints that answer 204 No Content.
func doPostNoContent(ctx context.Context, doer HTTPDoer, url string, data url.Values) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if doer == nil {
		doer = defaultHTTPClient()
	}
	resp, err := doer.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("request failed with status: %v", resp.Status)
	}
	return nil
}
