package vmlab

import (
	"bufio"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"strconv"
)

// maxScreendumpPixels bounds a decoded QEMU screendump (8K UHD) so a hostile
// or corrupt header cannot request an arbitrary allocation.
const maxScreendumpPixels = 7680 * 4320

// decodeScreendumpPPM decodes the binary PPM (P6, maxval 255) that QEMU's QMP
// screendump writes. Only that exact format is accepted; anything else is an
// observation failure rather than a best-effort guess.
func decodeScreendumpPPM(r io.Reader) (*image.RGBA, error) {
	reader := bufio.NewReader(r)
	var header [4]int
	magic, err := ppmToken(reader)
	if err != nil {
		return nil, err
	}
	if magic != "P6" {
		return nil, errors.New("screendump is not a binary PPM")
	}
	for i := 1; i < len(header); i++ {
		token, err := ppmToken(reader)
		if err != nil {
			return nil, err
		}
		header[i], err = strconv.Atoi(token)
		if err != nil || header[i] <= 0 {
			return nil, errors.New("screendump PPM header is invalid")
		}
	}
	width, height, maxval := header[1], header[2], header[3]
	if maxval != 255 {
		return nil, errors.New("screendump PPM must use 8-bit samples")
	}
	if width > maxScreendumpPixels/height {
		return nil, errors.New("screendump dimensions exceed the evidence bound")
	}
	// Exactly one whitespace byte separates the header from raster data.
	if _, err := reader.ReadByte(); err != nil {
		return nil, fmt.Errorf("read screendump PPM header: %w", err)
	}
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	row := make([]byte, width*3)
	for y := range height {
		if _, err := io.ReadFull(reader, row); err != nil {
			return nil, fmt.Errorf("read screendump PPM raster: %w", err)
		}
		offset := y * img.Stride
		for x := range width {
			copy(img.Pix[offset+x*4:offset+x*4+3], row[x*3:x*3+3])
			img.Pix[offset+x*4+3] = 0xff
		}
	}
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		return nil, errors.New("screendump PPM has trailing data")
	}
	return img, nil
}

// ppmToken reads one whitespace-delimited header token, skipping comments.
func ppmToken(reader *bufio.Reader) (string, error) {
	var token []byte
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return "", fmt.Errorf("read screendump PPM header: %w", err)
		}
		switch {
		case b == '#' && len(token) == 0:
			if _, err := reader.ReadString('\n'); err != nil {
				return "", fmt.Errorf("read screendump PPM comment: %w", err)
			}
		case b == ' ' || b == '\t' || b == '\n' || b == '\r':
			if len(token) != 0 {
				// The caller consumes the single raster separator itself.
				return string(token), reader.UnreadByte()
			}
		default:
			if len(token) >= 16 {
				return "", errors.New("screendump PPM header token is too long")
			}
			token = append(token, b)
		}
	}
}

// encodeScreendumpPNG writes lossless evidence; PNG keeps the exact pixels the
// button locators analysed.
func encodeScreendumpPNG(w io.Writer, img image.Image) error {
	encoder := png.Encoder{CompressionLevel: png.BestSpeed}
	return encoder.Encode(w, img)
}
