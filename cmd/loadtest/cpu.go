package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CPU accounting from /proc (Linux only; empty elsewhere). On a shared box
// throughput alone is misleading, so the report also shows how many
// CPU-seconds each process group (api, postgres, redis, this load generator)
// burned, how much went to everything else, and the cost per request.

const clockTicks = 100 // USER_HZ; 100 on every mainstream Linux build

// cpuSample is cumulative CPU seconds per process (keyed "group/pid"),
// plus "_busy" for the whole machine.
type cpuSample map[string]float64

func sampleCPU(groups []string) cpuSample {
	out := cpuSample{}
	self := strconv.Itoa(os.Getpid())
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		b, err := os.ReadFile(d + "/stat")
		if err != nil {
			continue
		}
		s := string(b)
		open, end := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
		if open < 0 || end < open {
			continue
		}
		comm := s[open+1 : end]
		f := strings.Fields(s[end+1:])
		if len(f) < 13 {
			continue
		}
		ut, _ := strconv.ParseFloat(f[11], 64)
		st, _ := strconv.ParseFloat(f[12], 64)
		secs := (ut + st) / clockTicks
		g := "other"
		if filepath.Base(d) == self {
			g = "loadtest"
		} else {
			for _, name := range groups {
				if strings.HasPrefix(comm, name) {
					g = name
					break
				}
			}
		}
		out[g+"/"+filepath.Base(d)] = secs
	}
	if b, err := os.ReadFile("/proc/stat"); err == nil {
		line, _, _ := strings.Cut(string(b), "\n")
		f := strings.Fields(line)
		var total, idle float64
		for i, v := range f[1:] {
			x, _ := strconv.ParseFloat(v, 64)
			total += x
			if i == 3 || i == 4 { // idle, iowait
				idle += x
			}
		}
		out["_busy"] = (total - idle) / clockTicks
	}
	return out
}

// cpuDelta is per-group CPU seconds between two samples, computed per
// process: a process that exited during the run is not counted (its
// cumulative total must not be subtracted from the group), one that started
// during the run counts in full.
func cpuDelta(a, b cpuSample) map[string]float64 {
	out := map[string]float64{}
	for k, v := range b {
		d := v - a[k]
		if d < 0 {
			d = 0
		}
		if k == "_busy" {
			out[k] = d
			continue
		}
		g, _, _ := strings.Cut(k, "/")
		out[g] += d
	}
	return out
}
