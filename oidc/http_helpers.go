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
	defer resp.Body.Close()

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
	req, err := http.NewRequest("POST", url, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(username, password)

	return doRequestAndUnmarshallJSON[T](ctx, doer, req)
}

func doPost[T any](ctx context.Context, doer HTTPDoer, url string, data url.Values) (*T, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return doRequestAndUnmarshallJSON[T](ctx, doer, req)
}
