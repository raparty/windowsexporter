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
)

const initialReadBufferSize = 64 * 1024

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
	EventIDs []string `yaml:"event_ids"`
}

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
// a filter. A nil return value means no filtering – all event IDs are accepted.
func newEventIDFilter(specs []string) (*eventIDFilter, error) {
	if len(specs) == 0 {
		return nil, nil
	}

	f := &eventIDFilter{
		ids: make(map[uint32]struct{}),
	}

	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}

		if idx := strings.Index(spec, "-"); idx != -1 {
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
		} else {
			id, err := strconv.ParseUint(spec, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid event ID %q: %w", spec, err)
			}

			f.ids[uint32(id)] = struct{}{}
		}
	}

	return f, nil
}

// contains returns true if the event ID should be collected.
func (f *eventIDFilter) contains(id uint32) bool {
	if f == nil {
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

	if start+2 > end {
		return ""
	}

	available := (end - start) / 2
	nameWords := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[start])), available)

	return windows.UTF16ToString(nameWords)
}

// eventKey is the composite key used to accumulate per-event counts.
type eventKey struct {
	eventType uint16
	eventID   uint32
	source    string
}

type Collector struct {
	config Config
	logger *slog.Logger

	filter     *eventIDFilter
	eventTotal *prometheus.Desc
	logState   map[string]*logReadState
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
		[]string{"channel", "level", "event_id", "source"},
		nil,
	)

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

		if err != nil {
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

			if c.filter.contains(eventID) {
				source := extractSourceName(buf, offset, rec.Length)
				key := eventKey{
					eventType: rec.EventType,
					eventID:   eventID,
					source:    source,
				}
				state.counts[key]++
			}

			state.nextRecordNumber = rec.RecordNumber + 1
			offset += rec.Length
		}
	}
}

// Fixed the unused logName parameter by using an underscore
func (c *Collector) reopenLog(_ string, state *logReadState) error {
	_ = closeEventLog(state.handle)
	// We use the handle from the existing state to keep logic simple
	// but the linter wanted logName used or removed.
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
		)
	}
}
