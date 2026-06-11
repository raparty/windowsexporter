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

package eventlog

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
)

const Name = "eventlog"

// Windows Event Log type constants.
const (
	eventlogSuccess      uint16 = 0x0000
	eventlogError        uint16 = 0x0001
	eventlogWarning      uint16 = 0x0002
	eventlogInformation  uint16 = 0x0004
	eventlogAuditSuccess uint16 = 0x0008
	eventlogAuditFailure uint16 = 0x0010
)

const (
	eventlogSequentialRead uint32 = 0x0001
	eventlogForwardsRead   uint32 = 0x0004
	utf16CharSize          uint32 = 2 // bytes per UTF-16 code unit
)

const initialReadBufferSize = 64 * 1024

// Boot performance event constants
const (
	diagnosticsChannel = "Microsoft-Windows-Diagnostics-Performance/Operational"
	bootPerfXPath      = "*[System[EventID=100]]"
)

//nolint:gochecknoglobals
var eventLevelNames = map[uint16]string{
	eventlogSuccess:      "success",
	eventlogError:        "error",
	eventlogWarning:      "warning",
	eventlogInformation:  "information",
	eventlogAuditSuccess: "audit_success",
	eventlogAuditFailure: "audit_failure",
}

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

//nolint:gochecknoglobals
var (
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")

	procOpenEventLogW              = modadvapi32.NewProc("OpenEventLogW")
	procCloseEventLog              = modadvapi32.NewProc("CloseEventLog")
	procGetNumberOfEventLogRecords = modadvapi32.NewProc("GetNumberOfEventLogRecords")
	procGetOldestEventLogRecord    = modadvapi32.NewProc("GetOldestEventLogRecord")
	procReadEventLogW              = modadvapi32.NewProc("ReadEventLogW")
)

func openEventLog(logName string) (windows.Handle, error) {
	logNamePtr, err := windows.UTF16PtrFromString(logName)
	if err != nil {
		return 0, fmt.Errorf("convert log name: %w", err)
	}

	ret, _, err := procOpenEventLogW.Call(0, uintptr(unsafe.Pointer(logNamePtr)))
	if ret == 0 {
		return 0, fmt.Errorf("OpenEventLogW: %w", err)
	}

	return windows.Handle(ret), nil
}

func closeEventLog(handle windows.Handle) error {
	ret, _, err := procCloseEventLog.Call(uintptr(handle))
	if ret == 0 {
		return fmt.Errorf("CloseEventLog: %w", err)
	}

	return nil
}

func getNumberOfEventLogRecords(handle windows.Handle) (uint32, error) {
	var count uint32

	ret, _, err := procGetNumberOfEventLogRecords.Call(uintptr(handle), uintptr(unsafe.Pointer(&count)))
	if ret == 0 {
		return 0, fmt.Errorf("GetNumberOfEventLogRecords: %w", err)
	}

	return count, nil
}

func getOldestEventLogRecord(handle windows.Handle) (uint32, error) {
	var oldest uint32

	ret, _, err := procGetOldestEventLogRecord.Call(uintptr(handle), uintptr(unsafe.Pointer(&oldest)))
	if ret == 0 {
		return 0, fmt.Errorf("GetOldestEventLogRecord: %w", err)
	}

	return oldest, nil
}

func readEventLog(handle windows.Handle, readFlags, recordOffset uint32, buf []byte) (uint32, uint32, error) {
	var bytesRead, minBytesNeeded uint32

	ret, _, err := procReadEventLogW.Call(
		uintptr(handle),
		uintptr(readFlags),
		uintptr(recordOffset),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&bytesRead)),
		uintptr(unsafe.Pointer(&minBytesNeeded)),
	)

	if ret == 0 {
		return 0, minBytesNeeded, err
	}

	return bytesRead, 0, nil
}

type Config struct {
	LogNames []string `yaml:"log_names"`
	EventIDs []string `yaml:"event_ids"` //nolint:tagliatelle
}

//nolint:gochecknoglobals
var ConfigDefaults = Config{
	LogNames: []string{"Application", "System"},
	EventIDs: []string{"15", "55", "41", "1000", "100", "400-499"},
}

// eventIDFilter stores parsed event IDs for efficient containment checks.
type eventIDFilter struct {
	ids    map[uint32]struct{}
	ranges [][2]uint32
}

// newEventIDFilter parses a slice of event ID specs (e.g., "15", "400-499") into
// a filter. An empty specs slice means no filtering – all event IDs are accepted.
func newEventIDFilter(specs []string) (*eventIDFilter, error) {
	f := &eventIDFilter{
		ids: make(map[uint32]struct{}),
	}

	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}

		idx := strings.Index(spec, "-")
		if idx == -1 {
			id, err := strconv.ParseUint(spec, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid event ID %q: %w", spec, err)
			}

			f.ids[uint32(id)] = struct{}{}

			continue
		}

		lo, err := strconv.ParseUint(spec[:idx], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid event ID range %q: %w", spec, err)
		}

		hi, err := strconv.ParseUint(spec[idx+1:], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid event ID range %q: %w", spec, err)
		}

		if lo > hi {
			return nil, fmt.Errorf("invalid event ID range %q: low > high", spec)
		}

		f.ranges = append(f.ranges, [2]uint32{uint32(lo), uint32(hi)})
	}

	return f, nil
}

// contains returns true if the event ID should be collected.
// An empty filter (no IDs and no ranges) accepts all event IDs.
func (f *eventIDFilter) contains(id uint32) bool {
	if len(f.ids) == 0 && len(f.ranges) == 0 {
		return true
	}

	if _, ok := f.ids[id]; ok {
		return true
	}

	for _, r := range f.ranges {
		if id >= r[0] && id <= r[1] {
			return true
		}
	}

	return false
}

// extractSourceName reads the SourceName field (UTF-16LE, null-terminated) that
// immediately follows the fixed-size EVENTLOGRECORD header.
func extractSourceName(buf []byte, recordOffset, recLen uint32) string {
	headerSize := uint32(unsafe.Sizeof(eventLogRecord{}))
	start := recordOffset + headerSize
	end := recordOffset + recLen

	if int(end) > len(buf) {
		end = uint32(len(buf))
	}

	if start+utf16CharSize > end {
		return ""
	}

	available := (end - start) / utf16CharSize
	nameWords := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[start])), available)

	return windows.UTF16ToString(nameWords)
}

// Event IDs used by the derived stability counters.
// These are always tracked regardless of the configurable event-ID filter.
const (
	eventIDApplicationError   uint32 = 1000 // Application log — faulting application crash
	eventIDApplicationHang    uint32 = 1002 // Application log — application not responding
	eventIDKernelPowerCrash   uint32 = 41   // System log — unexpected restart (BSOD / power loss)
	eventIDDisplayTDR         uint32 = 4101 // System log — display driver TDR recovery
	eventIDUnexpectedShutdown uint32 = 6008 // System log — previous shutdown was unexpected
)

// extractInsertionStrings parses the NumStrings null-terminated UTF-16LE
// strings stored at StringOffset inside an EVENTLOGRECORD.
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

// eventKey is the composite key used to accumulate per-event counts.
type eventKey struct {
	eventType          uint16
	eventID            uint32
	source             string
	faultingApplication string
}

type Collector struct {
	config Config
	logger *slog.Logger

	filter     *eventIDFilter
	eventTotal *prometheus.Desc
	logState   map[string]*logReadState

	// Derived stability counters — always tracked, not subject to the
	// configurable event-ID filter.  Cumulative since the exporter started.
	explorerCrashTotal      float64
	appHangTotal            float64
	displayResetTotal       float64
	unexpectedShutdownTotal float64
	kernelPowerCrashTotal   float64
	appCrashCounts          map[string]float64 // key = sanitized application name

	explorerCrashCount      *prometheus.Desc
	appHangCount            *prometheus.Desc
	displayResetCount       *prometheus.Desc
	unexpectedShutdownCount *prometheus.Desc
	kernelPowerCrashCount   *prometheus.Desc
	appCrashTotal           *prometheus.Desc

	// Boot performance metrics
	bootTimeMs      *prometheus.Desc
	mainPathBootTimeMs *prometheus.Desc
	postBootTimeMs  *prometheus.Desc
	bootStartupApps *prometheus.Desc
}

type logReadState struct {
	handle           windows.Handle
	nextRecordNumber uint32
	counts           map[eventKey]float64
}

func New(config *Config) *Collector {
	if config == nil {
		config = &ConfigDefaults
	}

	if config.LogNames == nil {
		config.LogNames = ConfigDefaults.LogNames
	}

	if config.EventIDs == nil {
		config.EventIDs = ConfigDefaults.EventIDs
	}

	return &Collector{config: *config}
}

func NewWithFlags(app *kingpin.Application) *Collector {
	c := &Collector{
		config: ConfigDefaults,
	}

	var logNames string

	app.Flag(
		"collector.eventlog.log-names",
		"Comma-separated list of Windows Event Log channels to collect. Defaults to Application and System.",
	).Default(strings.Join(ConfigDefaults.LogNames, ",")).StringVar(&logNames)

	var eventIDs string

	app.Flag(
		"collector.eventlog.event-ids",
		"Comma-separated list of event IDs (or ranges, e.g. 400-499) to collect. Defaults to 15,55,41,1000,100,400-499. Empty string collects all event IDs.",
	).Default(strings.Join(ConfigDefaults.EventIDs, ",")).StringVar(&eventIDs)

	app.Action(func(*kingpin.ParseContext) error {
		c.config.LogNames = strings.Split(logNames, ",")

		if eventIDs == "" {
			c.config.EventIDs = nil
		} else {
			c.config.EventIDs = strings.Split(eventIDs, ",")
		}

		return nil
	})

	return c
}

func (c *Collector) GetName() string {
	return Name
}

func (c *Collector) Build(logger *slog.Logger, _ *mi.Session) error {
	c.logger = logger.With(slog.String("collector", Name))

	filter, err := newEventIDFilter(c.config.EventIDs)
	if err != nil {
		return fmt.Errorf("parse event ID filter: %w", err)
	}

	c.filter = filter

	c.eventTotal = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "event_total"),
		"Total number of Windows Event Log events since the exporter started",
		[]string{"channel", "level", "event_id", "source", "faulting_application"},
		nil,
	)

	// Derived stability counters — no collector-name subsystem so the metric
	// names are windows_<name> rather than windows_eventlog_<name>.
	c.explorerCrashCount = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "explorer_crash_count"),
		"Total explorer.exe crash events (Application log Event 1000, faulting_application=Explorer.EXE) since the exporter started.",
		nil, nil,
	)
	c.appHangCount = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "application_hang_count"),
		"Total application-hang events (Application log Event 1002) since the exporter started.",
		nil, nil,
	)
	c.displayResetCount = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "display_reset_count"),
		"Total display driver TDR recovery events (System log Event 4101) since the exporter started.",
		nil, nil,
	)
	c.unexpectedShutdownCount = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "unexpected_shutdown_count"),
		"Total unexpected-shutdown events (System log Event 6008) since the exporter started.",
		nil, nil,
	)
	c.kernelPowerCrashCount = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "kernel_power_crash_count"),
		"Total kernel-power crash events (System log Event 41, e.g. BSOD or hard power loss) since the exporter started.",
		nil, nil,
	)
	c.appCrashTotal = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "app_crash_total"),
		"Total application crash events (Application log Event 1000) grouped by faulting application name since the exporter started.",
		[]string{"application"}, nil,
	)

	// Boot performance metrics
	c.bootTimeMs = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "boot_time_ms"),
		"Total boot duration in milliseconds from Microsoft-Windows-Diagnostics-Performance/Operational Event 100, field BootTime.",
		nil, nil,
	)
	c.mainPathBootTimeMs = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "mainpath_boot_time_ms"),
		"Main boot path duration in milliseconds from Microsoft-Windows-Diagnostics-Performance/Operational Event 100, field MainPathBootTime.",
		nil, nil,
	)
	c.postBootTimeMs = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "post_boot_time_ms"),
		"Post-boot duration in milliseconds from Microsoft-Windows-Diagnostics-Performance/Operational Event 100, field BootPostBootTime.",
		nil, nil,
	)
	c.bootStartupApps = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "boot_startup_apps"),
		"Number of startup applications recorded during boot from Microsoft-Windows-Diagnostics-Performance/Operational Event 100, field BootNumStartupApps.",
		nil, nil,
	)

	c.appCrashCounts = make(map[string]float64)

	c.logState = make(map[string]*logReadState, len(c.config.LogNames))

	for _, logName := range c.config.LogNames {
		handle, err := openEventLog(logName)
		if err != nil {
			return fmt.Errorf("open event log %q: %w", logName, err)
		}

		numRecords, err := getNumberOfEventLogRecords(handle)
		if err != nil {
			_ = closeEventLog(handle)

			return fmt.Errorf("get number of event log records for %q: %w", logName, err)
		}

		var nextRecord uint32
		if numRecords == 0 {
			nextRecord = 1
		} else {
			oldest, err := getOldestEventLogRecord(handle)
			if err != nil {
				_ = closeEventLog(handle)

				return fmt.Errorf("get oldest event log record for %q: %w", logName, err)
			}

			nextRecord = oldest + numRecords
		}

		c.logState[logName] = &logReadState{
			handle:           handle,
			nextRecordNumber: nextRecord,
			counts:           make(map[eventKey]float64),
		}
	}

	return nil
}

func (c *Collector) Close() error {
	for logName, state := range c.logState {
		if err := closeEventLog(state.handle); err != nil {
			c.logger.Warn("failed to close event log handle",
				slog.String("log", logName),
				slog.Any("err", err),
			)
		}
	}

	return nil
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) error {
	for logName, state := range c.logState {
		if err := c.collectLog(logName, state); err != nil {
			c.logger.Warn("failed to collect event log",
				slog.String("log", logName),
				slog.Any("err", err),
			)
		}

		c.emitCounts(ch, logName, state)
	}

	c.emitDerivedCounters(ch)
	c.collectBootPerformanceMetrics(ch)

	return nil
}

func (c *Collector) collectLog(logName string, state *logReadState) error {
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

		if errors.Is(err, windows.Errno(1503)) {
			return c.reopenLog(logName, state)
		}

		if err != nil {
			return fmt.Errorf("ReadEventLog: %w", err)
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

			// The low-order 16 bits of EventID contain the actual event ID.
			eventID := rec.EventID & 0xFFFF

			// Derived counters are updated for every record regardless of the
			// configurable filter, so they always reflect ground truth.
			c.updateDerivedCounters(buf, offset, eventID, rec)

			if c.filter.contains(eventID) && rec.EventType == eventlogError {
				source := extractSourceName(buf, offset, rec.Length)

				var faultingApplication string

				if eventID == eventIDApplicationError {
					if strs := extractInsertionStrings(buf, offset, rec); len(strs) > 0 {
						faultingApplication = sanitizeFaultingApplication(strs[0])
					}
				}

				key := eventKey{
					eventType:           rec.EventType,
					eventID:             eventID,
					source:              source,
					faultingApplication: faultingApplication,
				}
				state.counts[key]++
			}

			state.nextRecordNumber = rec.RecordNumber + 1
			offset += rec.Length
		}
	}
}

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

		return fmt.Errorf("get oldest event log record for %q after reopen: %w", logName, err)
	}

	state.handle = handle
	state.nextRecordNumber = oldest

	return nil
}

func (c *Collector) emitCounts(ch chan<- prometheus.Metric, logName string, state *logReadState) {
	for key, count := range state.counts {
		levelName, ok := eventLevelNames[key.eventType]
		if !ok {
			levelName = "unknown"
		}

		ch <- prometheus.MustNewConstMetric(
			c.eventTotal,
			prometheus.CounterValue,
			count,
			logName,
			levelName,
			strconv.FormatUint(uint64(key.eventID), 10),
			key.source,
			key.faultingApplication,
		)
	}
}

// updateDerivedCounters inspects a single event record and increments the
// appropriate derived stability counter. It is called for every record,
// independently of the configurable event-ID filter.
func (c *Collector) updateDerivedCounters(buf []byte, offset, eventID uint32, rec *eventLogRecord) {
	switch eventID {
	case eventIDKernelPowerCrash:
		c.kernelPowerCrashTotal++

	case eventIDApplicationError:
		// First insertion string is the faulting application name.
		if strs := extractInsertionStrings(buf, offset, rec); len(strs) > 0 {
			appName := sanitizeFaultingApplication(strs[0])
			if appName != "" {
				c.appCrashCounts[appName]++

				if strings.EqualFold(appName, "Explorer.EXE") {
					c.explorerCrashTotal++
				}
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

// emitDerivedCounters emits all collector-level derived stability metrics.
func (c *Collector) emitDerivedCounters(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.explorerCrashCount, prometheus.CounterValue, c.explorerCrashTotal)
	ch <- prometheus.MustNewConstMetric(c.appHangCount, prometheus.CounterValue, c.appHangTotal)
	ch <- prometheus.MustNewConstMetric(c.displayResetCount, prometheus.CounterValue, c.displayResetTotal)
	ch <- prometheus.MustNewConstMetric(c.unexpectedShutdownCount, prometheus.CounterValue, c.unexpectedShutdownTotal)
	ch <- prometheus.MustNewConstMetric(c.kernelPowerCrashCount, prometheus.CounterValue, c.kernelPowerCrashTotal)

	for appName, count := range c.appCrashCounts {
		ch <- prometheus.MustNewConstMetric(c.appCrashTotal, prometheus.CounterValue, count, appName)
	}
}

type bootPerformanceValues struct {
	bootTime         *float64
	mainPathBootTime *float64
	postBootTime     *float64
	startupApps      *float64
}

func parseBootPerformanceValues(fields map[string]string) (bootPerformanceValues, map[string]error) {
	values := bootPerformanceValues{}
	parseErrors := make(map[string]error)

	parse := func(fieldName string) *float64 {
		raw, ok := fields[fieldName]
		if !ok {
			return nil
		}

		value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err != nil {
			parseErrors[fieldName] = err

			return nil
		}

		return &value
	}

	values.bootTime = parse("BootTime")
	values.mainPathBootTime = parse("MainPathBootTime")
	values.postBootTime = parse("BootPostBootTime")
	values.startupApps = parse("BootNumStartupApps")

	return values, parseErrors
}

// collectBootPerformanceMetrics queries only the newest Event ID 100 and emits
// each available boot metric. Query and field errors never fail the scrape.
func (c *Collector) collectBootPerformanceMetrics(ch chan<- prometheus.Metric) {
	fields, err := wevtapi.QueryLatestEventData(diagnosticsChannel, bootPerfXPath)
	if err != nil {
		c.logger.Debug("failed to query boot performance metrics", slog.Any("err", err))

		return
	}

	if fields == nil {
		c.logger.Debug("no boot performance event found; skipping boot metrics")

		return
	}

	values, parseErrors := parseBootPerformanceValues(fields)
	for fieldName, parseErr := range parseErrors {
		c.logger.Debug("failed to parse boot performance field",
			slog.String("field", fieldName),
			slog.String("raw", fields[fieldName]),
			slog.Any("err", parseErr),
		)
	}

	emit := func(desc *prometheus.Desc, fieldName string, value *float64) {
		if value == nil {
			if _, malformed := parseErrors[fieldName]; !malformed {
				c.logger.Debug("boot performance field absent", slog.String("field", fieldName))
			}

			return
		}

		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, *value)
	}

	emit(c.bootTimeMs, "BootTime", values.bootTime)
	emit(c.mainPathBootTimeMs, "MainPathBootTime", values.mainPathBootTime)
	emit(c.postBootTimeMs, "BootPostBootTime", values.postBootTime)
	emit(c.bootStartupApps, "BootNumStartupApps", values.startupApps)
}
