// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"lindm/internal/agent/nativeexec"
)

const (
	pwDump          = "/usr/bin/pw-dump"
	pwDumpTimeout   = 10 * time.Second
	pwDumpOutput    = 8 << 20
	audioBitrate    = 64000
	maxAudioSources = 16
)

var audioElements = []string{"pipewiresrc", "audioconvert", "audioresample", "audiomixer", "opusenc", "rtpopuspay", "rtpstreampay", "fdsink"}

// PipeWireAudio lists the user's own PipeWire outputs and microphones and
// captures only the sources the employee selected locally. There is no audio
// portal: the employee's explicit choice in the product notification is the
// permission, and GNOME shows its own microphone-in-use indicator.
type PipeWireAudio struct {
	logger     *slog.Logger
	runtimeDir string
}

var _ AudioDevices = (*PipeWireAudio)(nil)

// NewPipeWireAudio binds the provider to the helper's own runtime directory.
func NewPipeWireAudio(logger *slog.Logger) (*PipeWireAudio, error) {
	if logger == nil {
		return nil, errors.New("desktop: missing audio logger")
	}
	runtime := os.Getenv("XDG_RUNTIME_DIR")
	if runtime != "/run/user/"+strconv.Itoa(os.Getuid()) {
		return nil, errors.New("desktop: XDG_RUNTIME_DIR is not the user's runtime directory")
	}
	return &PipeWireAudio{logger: logger, runtimeDir: runtime}, nil
}

type pwObject struct {
	Type string `json:"type"`
	Info struct {
		Props map[string]json.RawMessage `json:"props"`
	} `json:"info"`
}

func pwString(props map[string]json.RawMessage, key string) string {
	var value string
	if raw, ok := props[key]; ok && json.Unmarshal(raw, &value) == nil {
		return value
	}
	return ""
}

// Sources reports outputs (sinks) and microphones (sources), never monitors.
func (a *PipeWireAudio) Sources(ctx context.Context) ([]AudioSource, error) {
	if _, err := nativeexec.Executable(pwDump); err != nil {
		return nil, unavailable("pipewire_tools_missing", err)
	}
	result, err := nativeexec.Run(ctx, nativeexec.Command{
		Path: pwDump, Args: []string{"--no-colors"}, Env: []string{"XDG_RUNTIME_DIR=" + a.runtimeDir},
		Timeout: pwDumpTimeout, StdoutLimit: pwDumpOutput, StderrLimit: gstStderrTail,
	})
	if err != nil {
		return nil, unavailable("pipewire_unavailable", err)
	}
	return parseAudioSources(result.Stdout)
}

func parseAudioSources(data []byte) ([]AudioSource, error) {
	var objects []pwObject
	if err := json.Unmarshal(data, &objects); err != nil {
		return nil, unavailable("pipewire_dump_invalid", err)
	}
	var sources []AudioSource
	for _, object := range objects {
		if object.Type != "PipeWire:Interface:Node" {
			continue
		}
		props := object.Info.Props
		class := pwString(props, "media.class")
		microphone := class == "Audio/Source" || class == "Audio/Source/Virtual"
		if class != "Audio/Sink" && !microphone {
			continue
		}
		var serial uint64
		if raw, ok := props["object.serial"]; !ok || json.Unmarshal(raw, &serial) != nil || serial == 0 {
			continue
		}
		description := printableLabel(pwString(props, "node.description"))
		if description == "" {
			description = printableLabel(pwString(props, "node.name"))
		}
		if description == "" {
			continue
		}
		sources = append(sources, AudioSource{Serial: serial, Description: description, Microphone: microphone})
		if len(sources) == maxAudioSources {
			break
		}
	}
	return sources, nil
}

// printableLabel bounds a native description to the report's printable ASCII.
func printableLabel(value string) string {
	var out strings.Builder
	for _, r := range value {
		if out.Len() == 128 {
			break
		}
		if r < ' ' || r > '~' {
			r = '?'
		}
		out.WriteRune(r)
	}
	return strings.TrimSpace(out.String())
}

// Start encodes the selected output monitor and/or microphone to Opus RTP.
func (a *PipeWireAudio) Start(ctx context.Context, selected []AudioSource) (Capture, error) {
	if len(selected) == 0 || len(selected) > 2 {
		return nil, errors.New("audio selection invalid")
	}
	if _, err := nativeexec.Executable(gstLaunch); err != nil {
		return nil, unavailable("gst_launch_missing", err)
	}
	if err := checkElements(ctx, audioElements); err != nil {
		return nil, err
	}
	process, err := nativeexec.Start(ctx, nativeexec.Command{
		Path: gstLaunch, Args: audioArguments(selected), Env: []string{"XDG_RUNTIME_DIR=" + a.runtimeDir},
		Timeout: gstLifetime, StderrLimit: gstStderrTail,
	})
	if err != nil {
		return nil, unavailable("audio_start_failed", err)
	}
	a.logger.Info("audio pipeline started", "sources", len(selected))
	return &gstCapture{process: process, reader: newRTPStreamReader(process.Stdout()), logger: a.logger}, nil
}

// audioArguments targets PipeWire nodes by serial only: a native description
// never reaches the pipeline description.
func audioArguments(selected []AudioSource) []string {
	source := func(s AudioSource) []string {
		args := []string{"pipewiresrc", "target-object=" + strconv.FormatUint(s.Serial, 10), "do-timestamp=true"}
		if !s.Microphone {
			// An output is captured from its monitor, never as a microphone.
			args = append(args, "stream-properties=props,stream.capture.sink=true")
		}
		return append(args, "!", "audioconvert", "!", "audioresample", "!", "audio/x-raw,rate=48000,channels=2")
	}
	encode := []string{"opusenc", "bitrate=" + strconv.Itoa(audioBitrate), "frame-size=20",
		"!", "rtpopuspay", "pt=" + strconv.Itoa(opusPayloadType), "mtu=1200",
		"!", "rtpstreampay", "!", "fdsink", "fd=1"}
	args := []string{"-q"}
	if len(selected) == 1 {
		args = append(args, source(selected[0])...)
		return append(append(args, "!"), encode...)
	}
	args = append(append(args, "audiomixer", "name=mix", "!", "audioconvert", "!"), encode...)
	for _, s := range selected {
		args = append(append(args, source(s)...), "!", "mix.")
	}
	return args
}

func checkElements(ctx context.Context, elements []string) error {
	if _, err := nativeexec.Executable(gstInspect); err != nil {
		return unavailable("gst_inspect_missing", err)
	}
	ctx, cancel := context.WithTimeout(ctx, gstElementsTimeout)
	defer cancel()
	for _, element := range elements {
		if _, err := nativeexec.Run(ctx, nativeexec.Command{Path: gstInspect, Args: gstExistsArguments(element), Timeout: gstInspectTimeout, StdoutLimit: gstInspectStdout, StderrLimit: gstStderrTail}); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return unavailable(fmt.Sprintf("gst_element_missing:%s", element), err)
		}
	}
	return nil
}
