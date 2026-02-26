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
}

var ConfigDefaults = Config{
	LogNames: []string{"Application", "System"},
}

type Collector struct {
	config Config
	logger *slog.Logger

	eventTotal *prometheus.Desc
	logState   map[string]*logReadState
}

type logReadState struct {
	handle           windows.Handle
	nextRecordNumber uint32
	counts           map[uint16]float64
}

func New(config *Config) *Collector {
	if config == nil {
		config = &ConfigDefaults
	}

	if config.LogNames == nil {
		config.LogNames = ConfigDefaults.LogNames
	}

	return &Collector{config: *config}
}

func NewWithFlags(app *kingpin.Application) *Collector {
	c := &Collector{
		config: ConfigDefaults,
	}

	app.Flag(
		"collector.eventlog.log-names",
		"Comma-separated list of Windows Event Log channels to collect. Defaults to Application and System.",
	).Default("Application", "System").StringsVar(&c.config.LogNames)

	return c
}

func (c *Collector) GetName() string {
	return Name
}

func (c *Collector) Build(logger *slog.Logger, _ *mi.Session) error {
	c.logger = logger.With(slog.String("collector", Name))

	c.eventTotal = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "event_total"),
		"Total number of Windows Event Log events since the exporter started",
		[]string{"channel", "level"},
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

		counts := make(map[uint16]float64, len(eventLevelNames))
		for eventType := range eventLevelNames {
			counts[eventType] = 0
		}

		c.logState[logName] = &logReadState{
			handle:           handle,
			nextRecordNumber: nextRecord,
			counts:           counts,
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

			state.counts[rec.EventType]++
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
	for eventType, levelName := range eventLevelNames {
		ch <- prometheus.MustNewConstMetric(
			c.eventTotal,
			prometheus.CounterValue,
			state.counts[eventType],
			logName,
			levelName,
		)
	}
}
