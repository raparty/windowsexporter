//go:build windows

package eventlog

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"unsafe"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus-community/windows_exporter/internal/mi"
	"github.com/prometheus-community/windows_exporter/internal/types"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/windows"
)

const Name = "eventlog"

const (
	eventlogError uint16 = 0x0001
)

const (
	eventlogSeekRead     uint32 = 0x0002
	eventlogForwardsRead uint32 = 0x0004
)

const initialReadBufferSize = 64 * 1024

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
		return 0, err
	}
	ret, _, err := procOpenEventLogW.Call(0, uintptr(unsafe.Pointer(logNamePtr)))
	if ret == 0 {
		return 0, err
	}
	return windows.Handle(ret), nil
}

func closeEventLog(handle windows.Handle) error {
	ret, _, err := procCloseEventLog.Call(uintptr(handle))
	if ret == 0 {
		return err
	}
	return nil
}

func getNumberOfEventLogRecords(handle windows.Handle) (uint32, error) {
	var count uint32
	ret, _, err := procGetNumberOfEventLogRecords.Call(uintptr(handle), uintptr(unsafe.Pointer(&count)))
	if ret == 0 {
		return 0, err
	}
	return count, nil
}

func getOldestEventLogRecord(handle windows.Handle) (uint32, error) {
	var oldest uint32
	ret, _, err := procGetOldestEventLogRecord.Call(uintptr(handle), uintptr(unsafe.Pointer(&oldest)))
	if ret == 0 {
		return 0, err
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
	LogNames: []string{"Application", "System", "Microsoft-Windows-Diagnostics-Performance/Operational"},
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
	idCounts         map[uint32]float64
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
	c := &Collector{config: ConfigDefaults}
	var logNames string
	app.Flag("collector.eventlog.log-names", "Logs to watch.").Default(strings.Join(ConfigDefaults.LogNames, ",")).StringVar(&logNames)
	app.Action(func(*kingpin.ParseContext) error {
		c.config.LogNames = strings.Split(logNames, ",")
		return nil
	})
	return c
}

func (c *Collector) GetName() string { return Name }

func (c *Collector) Build(logger *slog.Logger, _ *mi.Session) error {
	c.logger = logger.With(slog.String("collector", Name))
	c.eventTotal = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "event_total"),
		"Total critical Windows Event Log errors by ID.",
		[]string{"channel", "level", "event_id"},
		nil,
	)
	c.logState = make(map[string]*logReadState)
	for _, logName := range c.config.LogNames {
		handle, err := openEventLog(logName)
		if err != nil {
			continue
		}
		num, _ := getNumberOfEventLogRecords(handle)
		old, _ := getOldestEventLogRecord(handle)
		c.logState[logName] = &logReadState{
			handle:           handle,
			nextRecordNumber: old + num,
			idCounts:         make(map[uint32]float64),
		}
	}
	return nil
}

func (c *Collector) Close() error {
	for _, state := range c.logState {
		_ = closeEventLog(state.handle)
	}
	return nil
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) error {
	for logName, state := range c.logState {
		_ = c.collectLog(logName, state)
		for id, count := range state.idCounts {
			ch <- prometheus.MustNewConstMetric(c.eventTotal, prometheus.CounterValue, count, logName, "error", fmt.Sprint(id))
		}
	}
	return nil
}

func (c *Collector) collectLog(logName string, state *logReadState) error {
	buf := make([]byte, initialReadBufferSize)
	for {
		bytesRead, minNeeded, err := readEventLog(state.handle, eventlogSeekRead|eventlogForwardsRead, state.nextRecordNumber, buf)
		if err != nil {
			if errors.Is(err, windows.ERROR_HANDLE_EOF) {
				return nil
			}
			if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
				buf = make([]byte, minNeeded)
				continue
			}
			if errors.Is(err, windows.Errno(1503)) {
				return c.reopenLog(logName, state)
			}
			return err
		}
		offset := uint32(0)
		for offset < bytesRead {
			rec := (*eventLogRecord)(unsafe.Pointer(&buf[offset]))
			eventID := rec.EventID & 0xFFFF
			if rec.EventType == eventlogError {
				isTarget := false
				switch eventID {
				case 15, 55, 41, 100, 1000:
					isTarget = true
				default:
					if eventID >= 400 && eventID <= 499 {
						isTarget = true
					}
				}
				if isTarget {
					state.idCounts[eventID]++
				}
			}
			state.nextRecordNumber = rec.RecordNumber + 1
			offset += rec.Length
		}
	}
}

func (c *Collector) reopenLog(logName string, state *logReadState) error {
	_ = closeEventLog(state.handle)
	h, err := openEventLog(logName)
	if err != nil {
		return err
	}
	state.handle = h
	num, _ := getNumberOfEventLogRecords(h)
	old, _ := getOldestEventLogRecord(h)
	state.nextRecordNumber = old + num
	return nil
}

