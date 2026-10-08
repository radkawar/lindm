package vmlab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Fetcher uses the system TLS roots and never follows a redirect away from the
// original HTTPS origin. Signed metadata remains mandatory even over HTTPS.
// Its zero value is ready to use. The private transport hook is for TLS fixtures.
type Fetcher struct {
	transport http.RoundTripper
}

func (f Fetcher) client() *http.Client {
	transport := f.transport
	if transport == nil {
		transport = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   20 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       30 * time.Second,
			DisableCompression:    true,
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many image source redirects")
			}
			if _, err := httpsURL(req.URL.String()); err != nil {
				return err
			}
			original := via[0].URL
			if !strings.EqualFold(req.URL.Host, original.Host) {
				return errors.New("image source redirect changes HTTPS origin")
			}
			return nil
		},
	}
}

// download creates a new private staging file and never opens an existing path
// for writing. The caller owns staging cleanup, including failed transfers.
func download(ctx context.Context, client *http.Client, root *os.Root, name, source string, limit int64, timeout time.Duration) (err error) {
	if _, err := httpsURL(source); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", source, err)
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", source, resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return fmt.Errorf("download exceeds %d-byte limit", limit)
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return fmt.Errorf("unexpected content encoding %q", encoding)
	}
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	written, err := io.Copy(file, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("download body: %w", err)
	}
	if written > limit {
		return fmt.Errorf("download exceeds %d-byte limit", limit)
	}
	if resp.ContentLength >= 0 && written != resp.ContentLength {
		return errors.New("download body is truncated")
	}
	return file.Sync()
}
