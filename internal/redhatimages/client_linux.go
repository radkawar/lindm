// Package redhatimages acquires official RHEL KVM images through Red Hat's
// authenticated download API. It does not register systems, accept subscriptions,
// build cloud images, or claim that authenticated checksums are vendor signatures.
package redhatimages

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/types/known/timestamppb"

	labv1 "lindm/gen/lindm/lab/v1"
)

const (
	tokenEndpoint = "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
	apiOrigin     = "https://api.access.redhat.com"
	metadataLimit = 4 << 20
	imageLimit    = 16 << 30
)

// Image is a selected upstream catalog row, not a serialized local configuration.
// The private download locator is never returned or persisted.
type Image struct {
	Filename  string
	SHA256    string
	Version   string
	Published time.Time
	Entitled  bool
}

// MetadataURL identifies the authenticated vendor publication without credentials.
func (i Image) MetadataURL() string {
	return apiOrigin + "/management/v1/images/rhel/" + i.Version + "/x86_64"
}

// DownloadURL is the stable checksum-addressed API locator, not the signed CDN URL.
func (i Image) DownloadURL() string {
	return apiOrigin + "/management/v1/images/" + i.SHA256 + "/download"
}

// Client keeps the short-lived bearer credential only in memory. Requests do not
// follow redirects; CDN requests are separate and never carry the API bearer.
type Client struct {
	http      *http.Client
	bearer    string
	tokenFile string
	expires   time.Time
	now       func() time.Time
	validator protovalidate.Validator
}

// New authenticates using a current-user-owned, mode-0600 regular token file.
// The offline token is sent only in an HTTPS refresh-grant request body.
func New(ctx context.Context, tokenFile string) (*Client, error) {
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          4,
		MaxConnsPerHost:       2,
		DisableCompression:    true,
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(new(labv1.VendorImageReceipt)))
	if err != nil {
		return nil, fmt.Errorf("redhatimages: compile receipt validation: %w", err)
	}
	c := &Client{http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, now: time.Now, validator: validator}
	if err := c.authenticate(ctx, tokenFile); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// Close releases pooled connections and drops the retained access-token reference.
func (c *Client) Close() { c.http.CloseIdleConnections(); c.bearer = ""; c.tokenFile = "" }

func readToken(filename string) (_ []byte, err error) {
	file, err := os.OpenFile(filename, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("redhatimages: cannot open offline token file")
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return nil, errors.New("redhatimages: cannot inspect offline token file")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("redhatimages: token must be a current-user-owned mode-0600 regular file, not a symlink")
	}
	data, err := io.ReadAll(io.LimitReader(file, 32769))
	if err != nil {
		return nil, errors.New("redhatimages: cannot read offline token file")
	}
	if len(data) == 0 || len(data) > 32768 {
		return nil, errors.New("redhatimages: token file is empty or exceeds 32768 bytes")
	}
	return data, nil
}

func (c *Client) authenticate(ctx context.Context, filename string) error {
	data, err := readToken(filename)
	if err != nil {
		return err
	}
	defer clear(data)
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"rhsm-api"}, "refresh_token": {strings.TrimSpace(string(data))}}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("redhatimages: cannot construct authentication request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("redhatimages: authentication HTTPS request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("redhatimages: authentication HTTP status %d", resp.StatusCode)
	}
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := decodeBounded(resp.Body, &token); err != nil {
		return err
	}
	if token.AccessToken == "" || !strings.EqualFold(token.TokenType, "bearer") || token.ExpiresIn <= 0 || token.ExpiresIn > 86400 {
		return errors.New("redhatimages: invalid access-token response")
	}
	c.bearer, c.tokenFile = token.AccessToken, filename
	c.expires = c.now().Add(time.Duration(token.ExpiresIn) * time.Second)
	return nil
}

func (c *Client) ensureBearer(ctx context.Context) error {
	if c.tokenFile == "" {
		return errors.New("redhatimages: authenticated client is closed")
	}
	if !c.now().Add(30 * time.Second).Before(c.expires) {
		return c.authenticate(ctx, c.tokenFile)
	}
	return nil
}

// Discover selects exactly one official x86_64 KVM qcow2 image for an explicit
// minor version. An absent entitlement is reported, never bypassed.
func (c *Client) Discover(ctx context.Context, version string) (Image, error) {
	major, minor, ok := strings.Cut(version, ".")
	n, err := strconv.ParseUint(minor, 10, 32)
	if !ok || (major != "9" && major != "10") || err != nil || strconv.FormatUint(n, 10) != minor {
		return Image{}, errors.New("redhatimages: version must be an explicit RHEL 9 or 10 minor, for example 9.8 or 10.2")
	}
	selected := Image{Version: version}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	resp, err := c.api(ctx, selected.MetadataURL())
	if err != nil {
		return Image{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Image{}, fmt.Errorf("redhatimages: image catalog HTTP status %d", resp.StatusCode)
	}
	// These fields decode the vendor-owned wire API, not a local config schema.
	var catalog struct {
		Body []struct {
			Filename      string `json:"filename"`
			Checksum      string `json:"checksum"`
			Arch          string `json:"arch"`
			DatePublished string `json:"datePublished"`
			DownloadHref  string `json:"downloadHref"`
		} `json:"body"`
	}
	if err := decodeBounded(resp.Body, &catalog); err != nil {
		return Image{}, err
	}
	matches := 0
	for _, row := range catalog.Body {
		if row.Filename != "rhel-"+version+"-x86_64-kvm.qcow2" || row.Arch != "x86_64" {
			continue
		}
		matches++
		published, err := time.Parse(time.RFC3339Nano, row.DatePublished)
		if err != nil {
			return Image{}, errors.New("redhatimages: invalid vendor publication timestamp")
		}
		digest, err := hex.DecodeString(row.Checksum)
		if err != nil || len(digest) != sha256.Size || strings.ToLower(row.Checksum) != row.Checksum {
			return Image{}, errors.New("redhatimages: invalid vendor SHA-256 publication")
		}
		selected.Filename, selected.SHA256, selected.Published = row.Filename, row.Checksum, published
		selected.Entitled = row.DownloadHref != ""
		if selected.Entitled && row.DownloadHref != selected.DownloadURL() {
			return Image{}, errors.New("redhatimages: unexpected vendor download API locator")
		}
	}
	if matches != 1 {
		return Image{}, fmt.Errorf("redhatimages: catalog contains %d matching official KVM images, expected one", matches)
	}
	return selected, nil
}

func (c *Client) api(ctx context.Context, endpoint string) (*http.Response, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host != "api.access.redhat.com" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || !strings.HasPrefix(u.Path, "/management/v1/images/") {
		return nil, errors.New("redhatimages: refused noncanonical API destination")
	}
	if err := c.ensureBearer(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errors.New("redhatimages: cannot construct API request")
	}
	req.Header.Set("Authorization", "Bearer "+c.bearer)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("redhatimages: API HTTPS request failed")
	}
	return resp, nil
}

func decodeBounded(r io.Reader, destination any) error {
	data, err := io.ReadAll(io.LimitReader(r, metadataLimit+1))
	if err != nil || len(data) > metadataLimit {
		return errors.New("redhatimages: metadata read failed or exceeded limit")
	}
	if err := json.Unmarshal(data, destination); err != nil {
		return errors.New("redhatimages: invalid vendor JSON response")
	}
	return nil
}

func cdnURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "access.cdn.redhat.com" || u.User != nil || u.Fragment != "" || u.Opaque != "" || !strings.HasPrefix(u.Path, "/content/origin/files/sha256/") {
		return errors.New("redhatimages: refused download destination outside the Red Hat CDN allowlist")
	}
	return nil
}

func (c *Client) cdn(ctx context.Context, method, endpoint string) (*http.Response, error) {
	if err := cdnURL(endpoint); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return nil, errors.New("redhatimages: cannot construct CDN request")
	}
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("redhatimages: CDN HTTPS request failed")
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "" {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("redhatimages: CDN rejected exact-byte request (HTTP %d)", resp.StatusCode)
	}
	return resp, nil
}

// Download streams the selected image to a new private temporary file, verifies
// the vendor SHA-256 and HEAD-published exact size, and returns sanitized receipt
// evidence. Caller owns removing the temporary file, including after cache import.
// No partial file survives a failure. The CDN URL remains memory-only.
func (c *Client) Download(ctx context.Context, image Image, directory string) (_ string, _ *labv1.VendorImageReceipt, err error) {
	if !image.Entitled {
		return "", nil, errors.New("redhatimages: Red Hat catalog does not grant download entitlement; enable Download Software and Updates permission and an eligible RHEL subscription")
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Minute)
	defer cancel()
	linkCtx, linkCancel := context.WithTimeout(ctx, time.Minute)
	resp, err := c.api(linkCtx, image.DownloadURL())
	if err != nil {
		linkCancel()
		return "", nil, err
	}
	var link struct {
		Body struct {
			Filename string `json:"filename"`
			Href     string `json:"href"`
		} `json:"body"`
	}
	if resp.StatusCode != http.StatusTemporaryRedirect && resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		linkCancel()
		return "", nil, fmt.Errorf("redhatimages: download authorization HTTP status %d (eligible subscription and download permission required)", resp.StatusCode)
	}
	decodeErr := decodeBounded(resp.Body, &link)
	closeErr := resp.Body.Close()
	linkCancel()
	if err := errors.Join(decodeErr, closeErr); err != nil {
		return "", nil, err
	}
	if link.Body.Filename != image.Filename {
		return "", nil, errors.New("redhatimages: download filename differs from catalog")
	}
	if err := cdnURL(link.Body.Href); err != nil {
		return "", nil, err
	}
	headCtx, headCancel := context.WithTimeout(ctx, time.Minute)
	head, err := c.cdn(headCtx, http.MethodHead, link.Body.Href)
	if err != nil {
		headCancel()
		return "", nil, err
	}
	size := head.ContentLength
	closeErr = head.Body.Close()
	headCancel()
	if closeErr != nil {
		return "", nil, errors.New("redhatimages: CDN size response close failed")
	}
	if size <= 0 || size > imageLimit {
		return "", nil, errors.New("redhatimages: CDN must publish an exact positive image size within 16 GiB")
	}
	receipt := &labv1.VendorImageReceipt{ImageFilename: image.Filename, Sha256: image.SHA256, ImageSizeBytes: uint64(size), Version: image.Version, Architecture: "x86_64", PublishedAt: timestamppb.New(image.Published), AcquiredAt: timestamppb.New(c.now()), MetadataUrl: image.MetadataURL()}
	if err := c.validator.Validate(receipt); err != nil {
		return "", nil, fmt.Errorf("redhatimages: invalid acquisition receipt: %w", err)
	}
	var filename string
	defer func() {
		if err != nil && filename != "" {
			err = errors.Join(err, os.Remove(filename))
		}
	}()
	body, err := c.cdn(ctx, http.MethodGet, link.Body.Href)
	if err != nil {
		return "", nil, err
	}
	defer func() { err = errors.Join(err, body.Body.Close()) }()
	if body.ContentLength != -1 && body.ContentLength != size {
		return "", nil, errors.New("redhatimages: CDN GET size differs from HEAD publication")
	}
	file, err := os.CreateTemp(directory, ".lindm-redhat-image-*")
	if err != nil {
		return "", nil, fmt.Errorf("redhatimages: create private staging image: %w", err)
	}
	filename = file.Name()
	defer func() { err = errors.Join(err, file.Close()) }()
	hash := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(body.Body, size+1))
	if copyErr != nil {
		return "", nil, errors.New("redhatimages: image transfer failed")
	}
	if count != size || hex.EncodeToString(hash.Sum(nil)) != image.SHA256 {
		return "", nil, errors.New("redhatimages: image bytes differ from the vendor-published SHA-256 or exact size")
	}
	if err := file.Sync(); err != nil {
		return "", nil, fmt.Errorf("redhatimages: sync acquired image: %w", err)
	}
	return filename, receipt, nil
}
