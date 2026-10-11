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
	// Each download bounds itself with its own context deadline; a fixed
	// client-wide cap would cut off pinned multi-gigabyte installer DVDs.
	return &http.Client{
		Transport: transport,
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

// maxDownloadResumes bounds how often an interrupted body is continued with an
// HTTP Range request. Every byte is still digest-verified afterwards.
const maxDownloadResumes = 8

// download creates a new private staging file and never opens an existing path
// for writing. The caller owns staging cleanup, including failed transfers.
// A body cut off mid-transfer (vendor mirrors drop long DVD connections) is
// continued from the exact written offset only when the first response
// declared the full length and the server answers with the matching range.
func download(ctx context.Context, client *http.Client, root *os.Root, name, source string, limit int64, timeout time.Duration) (err error) {
	if _, err := httpsURL(source); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var file *os.File
	defer func() {
		if file != nil {
			err = errors.Join(err, file.Close())
		}
	}()
	var written, total int64 = 0, -1
	for resumes := 0; ; resumes++ {
		n, done, err := downloadPart(ctx, client, root, name, source, limit, &file, written, &total)
		written += n
		if err == nil {
			if !done {
				return errors.New("download body is truncated")
			}
			return file.Sync()
		}
		var body *downloadBodyError
		if !errors.As(err, &body) || total < 0 || ctx.Err() != nil || resumes >= maxDownloadResumes {
			return err
		}
	}
}

// downloadBodyError marks a transfer interrupted after a valid response.
type downloadBodyError struct{ err error }

func (e *downloadBodyError) Error() string { return "download body: " + e.err.Error() }
func (e *downloadBodyError) Unwrap() error { return e.err }

// downloadPart fetches from offset written. The first part opens the private
// staging file and records the declared total length.
func downloadPart(ctx context.Context, client *http.Client, root *os.Root, name, source string, limit int64, file **os.File, written int64, total *int64) (_ int64, done bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return 0, false, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	if written > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", written))
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, false, fmt.Errorf("download %s: %w", source, err)
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return 0, false, fmt.Errorf("unexpected content encoding %q", encoding)
	}
	if written == 0 {
		if resp.StatusCode != http.StatusOK {
			return 0, false, fmt.Errorf("download %s: HTTP %d", source, resp.StatusCode)
		}
		if resp.ContentLength > limit {
			return 0, false, fmt.Errorf("download exceeds %d-byte limit", limit)
		}
		*total = resp.ContentLength
		if *file, err = root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600); err != nil {
			return 0, false, err
		}
	} else if resp.StatusCode != http.StatusPartialContent || resp.Header.Get("Content-Range") != fmt.Sprintf("bytes %d-%d/%d", written, *total-1, *total) {
		return 0, false, fmt.Errorf("download %s: resume at %d not honoured (HTTP %d)", source, written, resp.StatusCode)
	}
	n, err := io.Copy(*file, io.LimitReader(resp.Body, limit+1-written))
	if err != nil {
		return n, false, &downloadBodyError{err}
	}
	if written+n > limit {
		return n, false, fmt.Errorf("download exceeds %d-byte limit", limit)
	}
	return n, *total < 0 || written+n == *total, nil
}

// imageDownloadFloor is the slowest sustained vendor-mirror throughput a
// pinned image transfer is allowed before its deadline expires.
const imageDownloadFloor = 2 << 20 // bytes per second

// ImageDownloadTimeout bounds one pinned image transfer by its exact manifest
// size at imageDownloadFloor, never below the historical 30 minutes. Cloud
// images keep that floor; 10–15 GB installer DVDs get proportionally longer.
func ImageDownloadTimeout(size uint64) time.Duration {
	timeout := time.Duration(size/imageDownloadFloor+1) * time.Second
	return max(timeout, 30*time.Minute)
}
