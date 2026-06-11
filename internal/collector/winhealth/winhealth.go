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

// Package winhealth collects Windows system health and stability metrics.
//
// Boot performance metrics are sourced from the
// Microsoft-Windows-Diagnostics-Performance/Operational channel (Event 100),
// which records BootTime, BootPostBootTime, and BootNumStartupApps for every
// boot. Stability counters (crashes, hangs, shutdowns) accumulate new entries
// from the classic Application and System event logs using the advapi32
// sequential-read API. A pending-reboot indicator is derived from well-known
// registry keys updated by Windows Update, CBS, and installers.
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

// Name is the collector identifier used for registration, logging, and
// the --collectors.enabled flag.
const Name = "winhealth"

// diagnosticsChannel is the ETW/EVTX channel that records boot performance
// events. It is a modern channel-based log, not accessible via advapi32.
const diagnosticsChannel = "Microsoft-Windows-Diagnostics-Performance/Operational"

// bootPerfXPath selects the Boot Performance Measurement event. All three boot
// metrics are extracted from a single record of this type.
const bootPerfXPath = "*[System[EventID=100]]"

// Classic event log event IDs monitored as Prometheus counters.
// These events appear in the Application or System log and are read via advapi32.
const (
	eventIDKernelPowerCrash   uint32 = 41   // System  — unexpected power loss / BSOD restart
	eventIDApplicationError   uint32 = 1000 // App     — faulting application (crash)
	eventIDApplicationHang    uint32 = 1002 // App     — application not responding
	eventIDDisplayTDR         uint32 = 4101 // System  — display driver timeout & recovery
	eventIDUnexpectedShutdown uint32 = 6008 // System  — previous shutdown was unexpected
)

// advapi32 ReadEventLog flags (mirrors internal/collector/eventlog/eventlog.go).
const (
	evtlogSequentialRead  uint32 = 0x0001
	evtlogForwardsRead    uint32 = 0x0004
	utf16CharSize         uint32 = 2
	initialReadBufferSize        = 64 * 1024
)

//nolint:gochecknoglobals
var (
	modAdvapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procOpenEventLogW              = modAdvapi32.NewProc("OpenEventLogW")
	procCloseEventLog              = modAdvapi32.NewProc("CloseEventLog")
	procGetNumberOfEventLogRecords = modAdvapi32.NewProc("GetNumberOfEventLogRecords")
	procGetOldestEventLogRecord    = modAdvapi32.NewProc("GetOldestEventLogRecord")
	procReadEventLogW              = modAdvapi32.NewProc("ReadEventLogW")
)

// eventLogRecord mirrors the fixed-size EVENTLOGRECORD header defined in
// <winnt.h>. Variable-length fields (source name, strings, data) immediately
// follow this header in the buffer returned by ReadEventLog.
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

// logState holds the open handle and sequential read cursor for one event log.
type logState struct {
	handle           windows.Handle
	nextRecordNumber uint32
}

// Config holds collector-level configuration. Currently no tuneable options
// are exposed; the struct is reserved for future use.
type Config struct{}

//nolint:gochecknoglobals
var ConfigDefaults = Config{}

// Collector is the winhealth Prometheus collector.
type Collector struct {
	config Config
	logger *slog.Logger

	appLog *logState // Application log — crashes and hangs
	sysLog *logState // System log — display TDR, unexpected shutdown, kernel power

	// Cumulative counters incremented on each Collect call.
	explorerCrashTotal     float64
	appHangTotal           float64
	displayResetTotal      float64
	unexpectedShutdownTotal float64
	kernelPowerCrashTotal  float64

	// Prometheus metric descriptors.
	bootTimeMs             *prometheus.Desc
	postBootTimeMs         *prometheus.Desc
	bootStartupApps        *prometheus.Desc
	explorerCrashCount     *prometheus.Desc
	appHangCount           *prometheus.Desc
	displayResetCount      *prometheus.Desc
	unexpectedShutdownCount *prometheus.Desc
	kernelPowerCrashCount  *prometheus.Desc
	pendingReboot          *prometheus.Desc
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

// Close releases open event log handles.
func (c *Collector) Close() error {
	var errs []error

	if c.appLog != nil && c.appLog.handle != 0 {
		if err := closeEventLog(c.appLog.handle); err != nil {
			errs = append(errs, fmt.Errorf("close Application log: %w", err))
		}
	}

	if c.sysLog != nil && c.sysLog.handle != 0 {
		if err := closeEventLog(c.sysLog.handle); err != nil {
			errs = append(errs, fmt.Errorf("close System log: %w", err))
		}
	}

	return errors.Join(errs...)
}

// Build initialises metric descriptors and opens the event log handles.
// The miSession parameter is part of the Collector interface but is not used
// by this collector.
func (c *Collector) Build(logger *slog.Logger, _ *mi.Session) error {
	c.logger = logger.With(slog.String("collector", Name))

	// ── Boot performance (all from Diagnostics-Performance Event 100) ──────────
	c.bootTimeMs = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "boot_time_ms"),
		"Total boot duration in milliseconds "+
			"(Microsoft-Windows-Diagnostics-Performance/Operational Event 100, field BootTime).",
		nil, nil,
	)
	c.postBootTimeMs = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "post_boot_time_ms"),
		"Post-boot phase duration in milliseconds "+
			"(Microsoft-Windows-Diagnostics-Performance/Operational Event 100, field BootPostBootTime).",
		nil, nil,
	)
	c.bootStartupApps = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "boot_startup_apps"),
		"Number of startup applications that ran during the last boot "+
			"(Microsoft-Windows-Diagnostics-Performance/Operational Event 100, field BootNumStartupApps).",
		nil, nil,
	)

	// ── Stability counters (Application log) ───────────────────────────────────
	c.explorerCrashCount = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "explorer_crash_count"),
		"Total explorer.exe crash events observed since the exporter started "+
			"(Application log Event 1000, faulting application = explorer.exe).",
		nil, nil,
	)
	c.appHangCount = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "application_hang_count"),
		"Total application-hang events observed since the exporter started "+
			"(Application log Event 1002).",
		nil, nil,
	)

	// ── Stability counters (System log) ────────────────────────────────────────
	c.displayResetCount = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "display_reset_count"),
		"Total display driver TDR recovery events observed since the exporter started "+
			"(System log Event 4101).",
		nil, nil,
	)
	c.unexpectedShutdownCount = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "unexpected_shutdown_count"),
		"Total unexpected-shutdown events observed since the exporter started "+
			"(System log Event 6008).",
		nil, nil,
	)
	c.kernelPowerCrashCount = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "kernel_power_crash_count"),
		"Total kernel-power crash events observed since the exporter started "+
			"(System log Event 41, e.g. BSOD or hard power loss).",
		nil, nil,
	)

	// ── Pending reboot ─────────────────────────────────────────────────────────
	c.pendingReboot = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "pending_reboot"),
		"1 if a system reboot is currently pending, 0 otherwise. "+
			"Checks CBS, Windows Update, and PendingFileRenameOperations registry keys.",
		nil, nil,
	)

	// Open event logs, positioned at the current tail so only new events are
	// counted — consistent with the Prometheus counter-from-start convention.
	var err error

	c.appLog, err = openLogAtTail("Application")
	if err != nil {
		c.logger.Warn("failed to open Application event log; application stability metrics will be unavailable",
			slog.Any("err", err))
	}

	c.sysLog, err = openLogAtTail("System")
	if err != nil {
		c.logger.Warn("failed to open System event log; system stability metrics will be unavailable",
			slog.Any("err", err))
	}

	return nil
}

// Collect emits all winhealth metrics to ch.
func (c *Collector) Collect(ch chan<- prometheus.Metric) error {
	var errs []error

	if err := c.collectBootMetrics(ch); err != nil {
		errs = append(errs, fmt.Errorf("boot metrics: %w", err))
	}

	c.drainEventLogs()

	ch <- prometheus.MustNewConstMetric(c.explorerCrashCount, prometheus.CounterValue, c.explorerCrashTotal)
	ch <- prometheus.MustNewConstMetric(c.appHangCount, prometheus.CounterValue, c.appHangTotal)
	ch <- prometheus.MustNewConstMetric(c.displayResetCount, prometheus.CounterValue, c.displayResetTotal)
	ch <- prometheus.MustNewConstMetric(c.unexpectedShutdownCount, prometheus.CounterValue, c.unexpectedShutdownTotal)
	ch <- prometheus.MustNewConstMetric(c.kernelPowerCrashCount, prometheus.CounterValue, c.kernelPowerCrashTotal)

	pending := 0.0
	if isPendingReboot() {
		pending = 1.0
	}

	ch <- prometheus.MustNewConstMetric(c.pendingReboot, prometheus.GaugeValue, pending)

	return errors.Join(errs...)
}

// collectBootMetrics queries the Diagnostics-Performance channel for the most
// recent boot event (ID 100) and emits all three boot metrics from it.
func (c *Collector) collectBootMetrics(ch chan<- prometheus.Metric) error {
	fields, err := wevtapi.QueryLatestEventData(diagnosticsChannel, bootPerfXPath)
	if err != nil {
		return fmt.Errorf("query %s %s: %w", diagnosticsChannel, bootPerfXPath, err)
	}

	if fields == nil {
		// No boot event has been recorded yet; skip silently.
		return nil
	}

	emitMs := func(desc *prometheus.Desc, fieldName string) {
		raw, ok := fields[fieldName]
		if !ok {
			c.logger.Debug("boot event field not present", slog.String("field", fieldName))

			return
		}

		val, parseErr := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if parseErr != nil {
			c.logger.Warn("unparseable boot event field",
				slog.String("field", fieldName),
				slog.String("value", raw),
				slog.Any("err", parseErr),
			)

			return
		}

		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, val)
	}

	emitMs(c.bootTimeMs, "BootTime")
	emitMs(c.postBootTimeMs, "BootPostBootTime")
	emitMs(c.bootStartupApps, "BootNumStartupApps")

	return nil
}

// drainEventLogs reads any new records from both logs and updates counters.
func (c *Collector) drainEventLogs() {
	if c.appLog != nil {
		if err := c.scanLog(c.appLog, "Application"); err != nil {
			c.logger.Warn("error scanning Application event log", slog.Any("err", err))
		}
	}

	if c.sysLog != nil {
		if err := c.scanLog(c.sysLog, "System"); err != nil {
			c.logger.Warn("error scanning System event log", slog.Any("err", err))
		}
	}
}

// scanLog performs a sequential forward read of new records in state, updating
// the collector's counters for each matched event ID.
func (c *Collector) scanLog(state *logState, logName string) error {
	buf := make([]byte, initialReadBufferSize)

	for {
		bytesRead, minNeeded, err := readEventLog(
			state.handle,
			evtlogSequentialRead|evtlogForwardsRead,
			state.nextRecordNumber,
			buf,
		)

		switch {
		case errors.Is(err, windows.ERROR_HANDLE_EOF):
			return nil

		case errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER):
			if minNeeded > 0 {
				buf = make([]byte, minNeeded)
			} else {
				buf = make([]byte, len(buf)*2)
			}

			continue

		case errors.Is(err, windows.Errno(1503)): // ERROR_EVENTLOG_FILE_CHANGED
			return c.reopenLog(logName, state)

		case err != nil:
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

			// The low 16 bits of EventID carry the user-visible event identifier.
			eventID := rec.EventID & 0xFFFF

			c.handleEvent(buf, offset, eventID, rec)

			state.nextRecordNumber = rec.RecordNumber + 1
			offset += rec.Length
		}
	}
}

// handleEvent classifies a single event record and increments the matching counter.
func (c *Collector) handleEvent(buf []byte, offset, eventID uint32, rec *eventLogRecord) {
	switch eventID {
	case eventIDKernelPowerCrash:
		c.kernelPowerCrashTotal++

	case eventIDApplicationError:
		// Application Error events carry the faulting process name as the first
		// insertion string. Only count events where that string is "explorer.exe".
		if strs := extractInsertionStrings(buf, offset, rec); len(strs) > 0 {
			if strings.EqualFold(strs[0], "explorer.exe") {
				c.explorerCrashTotal++
			}
		}

	case eventIDApplicationHang:
		c.appHangTotal++

	case eventIDDisplayTDR:
		c.displayResetTotal++

	case eventIDUnexpectedShutdown:
		c.unexpectedShutdownTotal++
	}
}

// reopenLog handles log rotation (ERROR_EVENTLOG_FILE_CHANGED): closes the
// stale handle, reopens the log, and resets the cursor to the oldest record so
// no new events in the rotated file are missed.
func (c *Collector) reopenLog(logName string, state *logState) error {
	_ = closeEventLog(state.handle)

	state.handle = 0

	handle, err := openEventLog(logName)
	if err != nil {
		return fmt.Errorf("reopen %q after rotation: %w", logName, err)
	}

	oldest, err := getOldestEventLogRecord(handle)
	if err != nil {
		_ = closeEventLog(handle)

		return fmt.Errorf("get oldest record after reopen of %q: %w", logName, err)
	}

	state.handle = handle
	state.nextRecordNumber = oldest

	return nil
}

// openLogAtTail opens the named event log and positions the read cursor at the
// current end so that only events arriving after this call are counted.
func openLogAtTail(logName string) (*logState, error) {
	handle, err := openEventLog(logName)
	if err != nil {
		return nil, err
	}

	count, err := getNumberOfEventLogRecords(handle)
	if err != nil {
		_ = closeEventLog(handle)

		return nil, fmt.Errorf("get record count for %q: %w", logName, err)
	}

	var nextRecord uint32

	if count == 0 {
		nextRecord = 1
	} else {
		oldest, err := getOldestEventLogRecord(handle)
		if err != nil {
			_ = closeEventLog(handle)

			return nil, fmt.Errorf("get oldest record for %q: %w", logName, err)
		}

		nextRecord = oldest + count
	}

	return &logState{handle: handle, nextRecordNumber: nextRecord}, nil
}

// isPendingReboot returns true if any standard Windows pending-reboot indicator
// is present in the registry.
func isPendingReboot() bool {
	// Component-Based Servicing (Windows Update / patch installation).
	if registryKeyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`) {
		return true
	}

	// Windows Update auto-update reboot required.
	if registryKeyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`) {
		return true
	}

	// Installer file-rename operations deferred to next boot.
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

// registryKeyExists returns true when the HKLM key at path can be opened.
func registryKeyExists(path string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}

	k.Close()

	return true
}

// ── advapi32 event-log helpers ────────────────────────────────────────────────
// These mirror the unexported helpers in internal/collector/eventlog/eventlog.go.

func openEventLog(logName string) (windows.Handle, error) {
	ptr, err := windows.UTF16PtrFromString(logName)
	if err != nil {
		return 0, fmt.Errorf("encode log name %q: %w", logName, err)
	}

	ret, _, callErr := procOpenEventLogW.Call(0, uintptr(unsafe.Pointer(ptr)))
	if ret == 0 {
		return 0, fmt.Errorf("OpenEventLogW(%q): %w", logName, callErr)
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

	ret, _, callErr := procGetNumberOfEventLogRecords.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&count)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("GetNumberOfEventLogRecords: %w", callErr)
	}

	return count, nil
}

func getOldestEventLogRecord(handle windows.Handle) (uint32, error) {
	var oldest uint32

	ret, _, callErr := procGetOldestEventLogRecord.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&oldest)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("GetOldestEventLogRecord: %w", callErr)
	}

	return oldest, nil
}

func readEventLog(handle windows.Handle, flags, recordOffset uint32, buf []byte) (uint32, uint32, error) {
	var bytesRead, minNeeded uint32

	ret, _, callErr := procReadEventLogW.Call(
		uintptr(handle),
		uintptr(flags),
		uintptr(recordOffset),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&bytesRead)),
		uintptr(unsafe.Pointer(&minNeeded)),
	)
	if ret == 0 {
		return 0, minNeeded, callErr
	}

	return bytesRead, 0, nil
}

// extractInsertionStrings returns the NumStrings null-terminated UTF-16LE
// insertion strings stored at rec.StringOffset within buf.
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
		end := pos
		for end < len(words) && words[end] != 0 {
			end++
		}

		result = append(result, windows.UTF16ToString(words[pos:end]))
		pos = end + 1
	}

	return result
}
