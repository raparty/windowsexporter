// Copyright 2024 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build windows

// Package winhealth collects Windows health and stability metrics:
//   - Boot duration and post-boot duration from the Diagnostics-Performance event log
//   - Count of registered startup applications
//   - Counts of display driver resets, explorer crashes, and application hangs
//   - Whether a system reboot is currently pending
package winhealth

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"unsafe"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus-community/windows_exporter/internal/headers/wevtapi"
	"github.com/prometheus-community/windows_exporter/internal/mi"
	"github.com/prometheus-community/windows_exporter/internal/types"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Name is the collector name used for registration and logging.
const Name = "winhealth"

// Diagnostics-Performance event IDs used for boot timing.
const (
	eventIDBootPerf     uint32 = 100
	eventIDPostBootPerf uint32 = 200
)

// Windows Application/System log event IDs tracked as counters.
const (
	eventIDApplicationError uint32 = 1000
	eventIDApplicationHang  uint32 = 1002
	eventIDDisplayTDR       uint32 = 4101
)

// advapi32 sequential-read flags (mirrors eventlog collector).
const (
	eventlogSequentialRead uint32 = 0x0001
	eventlogForwardsRead   uint32 = 0x0004
	utf16CharSize          uint32 = 2
	initialReadBufferSize         = 64 * 1024
)

//nolint:gochecknoglobals
var (
	modadvapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procOpenEventLogW              = modadvapi32.NewProc("OpenEventLogW")
	procCloseEventLog              = modadvapi32.NewProc("CloseEventLog")
	procGetNumberOfEventLogRecords = modadvapi32.NewProc("GetNumberOfEventLogRecords")
	procGetOldestEventLogRecord    = modadvapi32.NewProc("GetOldestEventLogRecord")
	procReadEventLogW              = modadvapi32.NewProc("ReadEventLogW")
)

// eventLogRecord mirrors the Win32 EVENTLOGRECORD fixed-size header.
type eventLogRecord struct {
	Length              uint32
	Reserved            uint32
	RecordNumber        uint32
	TimeGenerated       uint32
	TimeWritten         uint32
	EventID             uint32
	EventType           uint16
	NumStrings          uint16
	EventCategory       uint16
	ReservedFlags       uint16
	ClosingRecordNumber uint32
	StringOffset        uint32
	UserSidLength       uint32
	UserSidOffset       uint32
	DataLength          uint32
	DataOffset          uint32
}

// logReadState tracks the per-log read cursor used in Collect.
type logReadState struct {
	handle           windows.Handle
	nextRecordNumber uint32
}

// startupCommand maps a single Win32_StartupCommand WMI result row.
type startupCommand struct {
	Name string `mi:"Name"`
}

// Config holds collector configuration (currently empty; reserved for future flags).
type Config struct{}

//nolint:gochecknoglobals
var ConfigDefaults = Config{}

// Collector implements the winhealth Prometheus collector.
type Collector struct {
	config Config
	logger *slog.Logger

	miSession         *mi.Session
	startupCmdQuery   mi.Query

	appLogState *logReadState
	sysLogState *logReadState

	// running counters updated each Collect
	explorerCrashTotal  float64
	appHangTotal        float64
	displayResetTotal   float64

	// metric descriptors
	bootTimeMs        *prometheus.Desc
	postBootTimeMs    *prometheus.Desc
	bootStartupApps   *prometheus.Desc
	displayResetCount *prometheus.Desc
	explorerCrashCount *prometheus.Desc
	appHangCount      *prometheus.Desc
	pendingReboot     *prometheus.Desc
}

func New(config *Config) *Collector {
	if config == nil {
		config = &ConfigDefaults
	}

	return &Collector{config: *config}
}

func NewWithFlags(_ *kingpin.Application) *Collector {
	return &Collector{}
}

func (c *Collector) GetName() string { return Name }

func (c *Collector) Close() error {
	if c.appLogState != nil && c.appLogState.handle != 0 {
		_ = closeEventLog(c.appLogState.handle)
	}

	if c.sysLogState != nil && c.sysLogState.handle != 0 {
		_ = closeEventLog(c.sysLogState.handle)
	}

	return nil
}

func (c *Collector) Build(logger *slog.Logger, miSession *mi.Session) error {
	c.logger = logger.With(slog.String("collector", Name))

	// Metric descriptors — names match the specification exactly.
	c.bootTimeMs = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "boot_time_ms"),
		"Duration of the last system boot in milliseconds, from the Diagnostics-Performance event log (Event ID 100).",
		nil, nil,
	)
	c.postBootTimeMs = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "post_boot_time_ms"),
		"Duration of the post-boot phase in milliseconds, from the Diagnostics-Performance event log (Event ID 200).",
		nil, nil,
	)
	c.bootStartupApps = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "boot_startup_apps"),
		"Number of applications registered to run at startup (Win32_StartupCommand).",
		nil, nil,
	)
	c.displayResetCount = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "display_reset_count"),
		"Total number of display driver TDR recovery events (System log Event ID 4101) since the exporter started.",
		nil, nil,
	)
	c.explorerCrashCount = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "explorer_crash_count"),
		"Total number of explorer.exe crashes (Application log Event ID 1000) since the exporter started.",
		nil, nil,
	)
	c.appHangCount = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "application_hang_count"),
		"Total number of application hang events (Application log Event ID 1002) since the exporter started.",
		nil, nil,
	)
	c.pendingReboot = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "pending_reboot"),
		"1 if a system reboot is currently pending, 0 otherwise.",
		nil, nil,
	)

	// WMI session for startup app count.
	if miSession == nil {
		return errors.New("miSession is nil")
	}

	c.miSession = miSession

	query, err := mi.NewQuery("SELECT Name FROM Win32_StartupCommand")
	if err != nil {
		return fmt.Errorf("create Win32_StartupCommand query: %w", err)
	}

	c.startupCmdQuery = query

	// Open Application and System event logs; position at the current tail so
	// only new events are counted (standard Prometheus counter pattern).
	c.appLogState, err = openLogAtTail("Application")
	if err != nil {
		c.logger.Warn("failed to open Application event log", slog.Any("err", err))
	}

	c.sysLogState, err = openLogAtTail("System")
	if err != nil {
		c.logger.Warn("failed to open System event log", slog.Any("err", err))
	}

	return nil
}

// Collect emits all winhealth metrics.
func (c *Collector) Collect(ch chan<- prometheus.Metric) error {
	errs := make([]error, 0, 4)

	if err := c.collectBootMetrics(ch); err != nil {
		errs = append(errs, fmt.Errorf("boot metrics: %w", err))
	}

	if err := c.collectStartupApps(ch); err != nil {
		errs = append(errs, fmt.Errorf("startup apps: %w", err))
	}

	c.collectEventCounters()

	ch <- prometheus.MustNewConstMetric(c.displayResetCount, prometheus.CounterValue, c.displayResetTotal)
	ch <- prometheus.MustNewConstMetric(c.explorerCrashCount, prometheus.CounterValue, c.explorerCrashTotal)
	ch <- prometheus.MustNewConstMetric(c.appHangCount, prometheus.CounterValue, c.appHangTotal)

	if err := c.collectPendingReboot(ch); err != nil {
		errs = append(errs, fmt.Errorf("pending reboot: %w", err))
	}

	return errors.Join(errs...)
}

// collectBootMetrics reads the most recent boot and post-boot durations from
// the Microsoft-Windows-Diagnostics-Performance/Operational event log.
func (c *Collector) collectBootMetrics(ch chan<- prometheus.Metric) error {
	const channel = "Microsoft-Windows-Diagnostics-Performance/Operational"

	// Event 100 → BootTime field gives total boot duration in ms.
	bootData, err := wevtapi.QueryLatestEventData(channel, "*[System[EventID=100]]")
	if err != nil {
		c.logger.Warn("failed to query boot time event", slog.Any("err", err))
	} else if bootData != nil {
		if raw, ok := bootData["BootTime"]; ok {
			if ms, parseErr := strconv.ParseFloat(strings.TrimSpace(raw), 64); parseErr == nil {
				ch <- prometheus.MustNewConstMetric(c.bootTimeMs, prometheus.GaugeValue, ms)
			}
		}
	}

	// Event 200 → MainPathBootTime field gives post-boot phase duration in ms.
	postData, err := wevtapi.QueryLatestEventData(channel, "*[System[EventID=200]]")
	if err != nil {
		c.logger.Warn("failed to query post-boot time event", slog.Any("err", err))
	} else if postData != nil {
		if raw, ok := postData["MainPathBootTime"]; ok {
			if ms, parseErr := strconv.ParseFloat(strings.TrimSpace(raw), 64); parseErr == nil {
				ch <- prometheus.MustNewConstMetric(c.postBootTimeMs, prometheus.GaugeValue, ms)
			}
		}
	}

	return nil
}

// collectStartupApps counts WMI Win32_StartupCommand entries.
func (c *Collector) collectStartupApps(ch chan<- prometheus.Metric) error {
	var dst []startupCommand

	if err := c.miSession.Query(&dst, mi.NamespaceRootCIMv2, c.startupCmdQuery); err != nil {
		return fmt.Errorf("WMI query Win32_StartupCommand: %w", err)
	}

	ch <- prometheus.MustNewConstMetric(c.bootStartupApps, prometheus.GaugeValue, float64(len(dst)))

	return nil
}

// collectEventCounters scans new entries in the Application and System event logs
// and updates the running crash/hang/display counters.
func (c *Collector) collectEventCounters() {
	if c.appLogState != nil {
		if err := c.scanLog(c.appLogState, "Application"); err != nil {
			c.logger.Warn("failed to scan Application event log", slog.Any("err", err))
		}
	}

	if c.sysLogState != nil {
		if err := c.scanLog(c.sysLogState, "System"); err != nil {
			c.logger.Warn("failed to scan System event log", slog.Any("err", err))
		}
	}
}

// scanLog reads newly arrived event log records and increments the appropriate counters.
func (c *Collector) scanLog(state *logReadState, logName string) error {
	buf := make([]byte, initialReadBufferSize)

	for {
		bytesRead, minNeeded, err := readEventLog(
			state.handle,
			eventlogSequentialRead|eventlogForwardsRead,
			state.nextRecordNumber,
			buf,
		)

		if errors.Is(err, windows.ERROR_HANDLE_EOF) {
			return nil
		}

		if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			if minNeeded > 0 {
				buf = make([]byte, minNeeded)
			} else {
				buf = make([]byte, len(buf)*2)
			}

			continue
		}

		// ERROR_EVENTLOG_FILE_CHANGED (1503): log was cleared/rotated — reopen.
		if errors.Is(err, windows.Errno(1503)) {
			return c.reopenLog(logName, state)
		}

		if err != nil {
			return fmt.Errorf("ReadEventLog %q: %w", logName, err)
		}

		offset := uint32(0)

		for offset < bytesRead {
			if offset+uint32(unsafe.Sizeof(eventLogRecord{})) > bytesRead {
				break
			}

			rec := (*eventLogRecord)(unsafe.Pointer(&buf[offset]))
			if rec.Length == 0 {
				break
			}

			// The low 16 bits of EventID carry the actual identifier.
			eventID := rec.EventID & 0xFFFF

			switch eventID {
			case eventIDDisplayTDR:
				c.displayResetTotal++

			case eventIDApplicationHang:
				c.appHangTotal++

			case eventIDApplicationError:
				// Only count crashes where the faulting application is explorer.exe.
				if strs := extractInsertionStrings(buf, offset, rec); len(strs) > 0 {
					if strings.EqualFold(strs[0], "explorer.exe") {
						c.explorerCrashTotal++
					}
				}
			}

			state.nextRecordNumber = rec.RecordNumber + 1
			offset += rec.Length
		}
	}
}

// collectPendingReboot checks well-known registry keys and emits 1 if any
// pending-reboot indicator is set, 0 otherwise.
func (c *Collector) collectPendingReboot(ch chan<- prometheus.Metric) error {
	pending := checkPendingReboot()

	val := 0.0
	if pending {
		val = 1.0
	}

	ch <- prometheus.MustNewConstMetric(c.pendingReboot, prometheus.GaugeValue, val)

	return nil
}

// checkPendingReboot returns true if any standard pending-reboot registry
// indicator is present on the local system.
func checkPendingReboot() bool {
	// CBS (Component-Based Servicing) reboot pending.
	if keyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`) {
		return true
	}

	// Windows Update reboot required.
	if keyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`) {
		return true
	}

	// Pending file rename operations (often set by installers).
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager`,
		registry.QUERY_VALUE,
	)
	if err == nil {
		defer k.Close()

		vals, _, rErr := k.GetStringsValue("PendingFileRenameOperations")
		if rErr == nil && len(vals) > 0 {
			return true
		}
	}

	return false
}

// keyExists returns true if the HKLM registry key at path can be opened.
func keyExists(path string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}

	k.Close()

	return true
}

// reopenLog handles log rotation: closes the stale handle and reopens from the
// oldest available record so no events in the new file are missed.
func (c *Collector) reopenLog(logName string, state *logReadState) error {
	_ = closeEventLog(state.handle)

	state.handle = 0

	handle, err := openEventLog(logName)
	if err != nil {
		return fmt.Errorf("reopen event log %q: %w", logName, err)
	}

	oldest, err := getOldestEventLogRecord(handle)
	if err != nil {
		_ = closeEventLog(handle)

		return fmt.Errorf("get oldest record after reopen %q: %w", logName, err)
	}

	state.handle = handle
	state.nextRecordNumber = oldest

	return nil
}

// openLogAtTail opens a named event log and positions the cursor at the tail
// (current end), so only future events are counted.
func openLogAtTail(logName string) (*logReadState, error) {
	handle, err := openEventLog(logName)
	if err != nil {
		return nil, err
	}

	numRecords, err := getNumberOfEventLogRecords(handle)
	if err != nil {
		_ = closeEventLog(handle)

		return nil, fmt.Errorf("get record count for %q: %w", logName, err)
	}

	var nextRecord uint32

	if numRecords == 0 {
		nextRecord = 1
	} else {
		oldest, err := getOldestEventLogRecord(handle)
		if err != nil {
			_ = closeEventLog(handle)

			return nil, fmt.Errorf("get oldest record for %q: %w", logName, err)
		}

		nextRecord = oldest + numRecords
	}

	return &logReadState{
		handle:           handle,
		nextRecordNumber: nextRecord,
	}, nil
}

// --- advapi32 helpers (mirrors internal/collector/eventlog/eventlog.go) ---

func openEventLog(logName string) (windows.Handle, error) {
	ptr, err := windows.UTF16PtrFromString(logName)
	if err != nil {
		return 0, fmt.Errorf("convert log name: %w", err)
	}

	ret, _, callErr := procOpenEventLogW.Call(0, uintptr(unsafe.Pointer(ptr)))
	if ret == 0 {
		return 0, fmt.Errorf("OpenEventLogW: %w", callErr)
	}

	return windows.Handle(ret), nil
}

func closeEventLog(handle windows.Handle) error {
	ret, _, callErr := procCloseEventLog.Call(uintptr(handle))
	if ret == 0 {
		return fmt.Errorf("CloseEventLog: %w", callErr)
	}

	return nil
}

func getNumberOfEventLogRecords(handle windows.Handle) (uint32, error) {
	var count uint32

	ret, _, callErr := procGetNumberOfEventLogRecords.Call(uintptr(handle), uintptr(unsafe.Pointer(&count)))
	if ret == 0 {
		return 0, fmt.Errorf("GetNumberOfEventLogRecords: %w", callErr)
	}

	return count, nil
}

func getOldestEventLogRecord(handle windows.Handle) (uint32, error) {
	var oldest uint32

	ret, _, callErr := procGetOldestEventLogRecord.Call(uintptr(handle), uintptr(unsafe.Pointer(&oldest)))
	if ret == 0 {
		return 0, fmt.Errorf("GetOldestEventLogRecord: %w", callErr)
	}

	return oldest, nil
}

func readEventLog(handle windows.Handle, readFlags, recordOffset uint32, buf []byte) (uint32, uint32, error) {
	var bytesRead, minBytesNeeded uint32

	ret, _, callErr := procReadEventLogW.Call(
		uintptr(handle),
		uintptr(readFlags),
		uintptr(recordOffset),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&bytesRead)),
		uintptr(unsafe.Pointer(&minBytesNeeded)),
	)
	if ret == 0 {
		return 0, minBytesNeeded, callErr
	}

	return bytesRead, 0, nil
}

// extractInsertionStrings parses the NumStrings null-terminated UTF-16LE strings
// stored at StringOffset inside an EVENTLOGRECORD.
func extractInsertionStrings(buf []byte, recordOffset uint32, rec *eventLogRecord) []string {
	if rec.NumStrings == 0 || rec.StringOffset == 0 {
		return nil
	}

	strStart := recordOffset + rec.StringOffset
	strEnd := recordOffset + rec.Length

	if int(strEnd) > len(buf) {
		strEnd = uint32(len(buf))
	}

	if strStart+utf16CharSize > strEnd {
		return nil
	}

	wordCount := (strEnd - strStart) / utf16CharSize
	words := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[strStart])), wordCount)

	result := make([]string, 0, rec.NumStrings)

	pos := 0

	for i := 0; i < int(rec.NumStrings) && pos < len(words); i++ {
		nul := pos
		for nul < len(words) && words[nul] != 0 {
			nul++
		}

		result = append(result, windows.UTF16ToString(words[pos:nul]))
		pos = nul + 1
	}

	return result
}
