package devlab

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// ScaleOutReplicaMetrics are process counters and cumulative accepted TCP
// sessions at each HAProxy backend. Connections are not HTTP request counts:
// HTTP/2 reuses a connection. CPU ticks are per-host, not an aggregate CPU rate.
type ScaleOutReplicaMetrics struct {
	Name              string `json:"name"`
	PID               int    `json:"pid"`
	CPUClockTicks     uint64 `json:"cpu_clock_ticks"`
	RSSBytes          uint64 `json:"rss_bytes"`
	EffectiveCPUs     string `json:"effective_cpus"`
	AdminConnections  uint64 `json:"admin_connections"`
	DeviceConnections uint64 `json:"device_connections"`
}

// MeasureScaleOut is deliberately separate from Measure, whose process counters
// still describe replica1. Call serially with fixture lifecycle operations.
func (f *AuthorityFixture) MeasureScaleOut(ctx context.Context) ([]ScaleOutReplicaMetrics, error) {
	if f == nil || f.closed || f.scaleOut == nil || f.process == nil {
		return nil, errors.New("scale-out metrics require a running scale-out fixture")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	counts, err := f.scaleOut.connectionCounts(ctx)
	if err != nil {
		return nil, err
	}
	metrics := make([]ScaleOutReplicaMetrics, 0, len(f.scaleOut.environment.Replicas))
	for _, replica := range f.scaleOut.environment.Replicas {
		var sample ScaleOutReplicaMetrics
		if replica.Name == "replica2" {
			sample, err = f.scaleOut.sampleRemote(ctx)
		} else {
			sample, err = scaleOutProcessMetrics(replica.PID)
		}
		if err != nil {
			return nil, fmt.Errorf("measure %s: %w", replica.Name, err)
		}
		if sample.PID != replica.PID {
			return nil, fmt.Errorf("replica %s process identity changed", replica.Name)
		}
		sample.Name = replica.Name
		var adminOK, deviceOK bool
		sample.AdminConnections, adminOK = counts["admin/"+replica.Name]
		sample.DeviceConnections, deviceOK = counts["device/"+replica.Name]
		if !adminOK || !deviceOK {
			return nil, fmt.Errorf("balancer omitted %s routing counters", replica.Name)
		}
		metrics = append(metrics, sample)
	}
	return metrics, nil
}

func (t *scaleOutTopology) sampleRemote(ctx context.Context) (ScaleOutReplicaMetrics, error) {
	var sample ScaleOutReplicaMetrics
	data, err := t.remoteCommand(ctx, "sample", nil)
	if err != nil {
		return sample, err
	}
	if err := json.Unmarshal(data, &sample); err != nil {
		return sample, err
	}
	if sample.PID < 1 || sample.EffectiveCPUs == "" || validateLoadCPUList(sample.EffectiveCPUs) != nil {
		return sample, errors.New("remote replica omitted process or affinity evidence")
	}
	return sample, nil
}

func scaleOutProcessMetrics(pid int) (ScaleOutReplicaMetrics, error) {
	sample := ScaleOutReplicaMetrics{PID: pid}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return sample, err
	}
	sample.CPUClockTicks, sample.RSSBytes, err = scaleOutProcessCounters(string(data), uint64(os.Getpagesize()))
	if err != nil {
		return sample, err
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return sample, err
	}
	sample.EffectiveCPUs, err = loadPostgresEffectiveCPUs(string(status))
	return sample, err
}

func scaleOutProcessCounters(stat string, pageBytes uint64) (ticks, rss uint64, err error) {
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return 0, 0, errors.New("invalid replica process stat")
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 22 {
		return 0, 0, errors.New("short replica process stat")
	}
	user, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	system, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	pages, err := strconv.ParseUint(fields[21], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	return user + system, pages * pageBytes, nil
}

func (t *scaleOutTopology) connectionCounts(ctx context.Context) (_ map[string]uint64, resultErr error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(t.proxy.statsPort)))
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, conn.Close()) }()
	deadline := time.Now().Add(5 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(conn, "show stat\n"); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(conn, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, errors.New("scale-out proxy statistics exceeded bound")
	}
	return scaleOutConnectionCounts(string(data))
}

func scaleOutConnectionCounts(data string) (map[string]uint64, error) {
	reader := csv.NewReader(strings.NewReader(data))
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return nil, err
	}
	columns := make(map[string]int, len(header))
	for index, name := range header {
		columns[strings.TrimSpace(strings.TrimPrefix(name, "#"))] = index
	}
	for _, name := range []string{"pxname", "svname", "stot"} {
		if _, ok := columns[name]; !ok {
			return nil, fmt.Errorf("HAProxy statistics omitted %s", name)
		}
	}
	counts := make(map[string]uint64)
	for {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return counts, nil
		}
		if err != nil {
			return nil, err
		}
		for _, name := range []string{"pxname", "svname", "stot"} {
			if columns[name] >= len(row) {
				return nil, errors.New("short HAProxy statistics row")
			}
		}
		backend, server := row[columns["pxname"]], row[columns["svname"]]
		if server == "FRONTEND" || server == "BACKEND" {
			continue
		}
		count, err := strconv.ParseUint(row[columns["stot"]], 10, 64)
		if err != nil {
			return nil, err
		}
		key := backend + "/" + server
		if _, exists := counts[key]; exists {
			return nil, errors.New("duplicate HAProxy replica counter")
		}
		counts[key] = count
	}
}
