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

// Package wevtapi provides a thin wrapper around the Windows Event Log API
// (wevtapi.dll) for querying channel-based (ETW/EVTX) event logs that are not
// accessible via the classic advapi32 OpenEventLog/ReadEventLog interface.
package wevtapi

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// EvtQuery flags.
const (
	evtQueryChannelPath      uint32 = 0x00000001
	evtQueryReverseDirection uint32 = 0x00000200
	evtRenderEventXml        uint32 = 1

	// errNoMoreItems is the Win32 error code returned by EvtNext when the
	// result set is exhausted.
	errNoMoreItems = windows.Errno(259)
)

//nolint:gochecknoglobals
var (
	modWevtapi    = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery  = modWevtapi.NewProc("EvtQuery")
	procEvtNext   = modWevtapi.NewProc("EvtNext")
	procEvtRender = modWevtapi.NewProc("EvtRender")
	procEvtClose  = modWevtapi.NewProc("EvtClose")
)

// QueryLatestEventData queries the named Windows Event Log channel for the
// most recent event matching the XPath query string and returns the EventData
// fields as a Name→Value map. Returns nil, nil when no matching event exists.
func QueryLatestEventData(channel, query string) (map[string]string, error) {
	channelPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return nil, fmt.Errorf("encode channel name: %w", err)
	}

	queryPtr, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return nil, fmt.Errorf("encode query string: %w", err)
	}

	queryHandle, _, callErr := procEvtQuery.Call(
		0, // local session
		uintptr(unsafe.Pointer(channelPtr)),
		uintptr(unsafe.Pointer(queryPtr)),
		uintptr(evtQueryChannelPath|evtQueryReverseDirection),
	)
	if queryHandle == 0 {
		return nil, fmt.Errorf("EvtQuery: %w", callErr)
	}

	defer procEvtClose.Call(queryHandle) //nolint:errcheck

	var eventHandle windows.Handle

	var returned uint32

	ret, _, callErr := procEvtNext.Call(
		queryHandle,
		1,
		uintptr(unsafe.Pointer(&eventHandle)),
		2000, // timeout in milliseconds
		0,    // reserved flags
		uintptr(unsafe.Pointer(&returned)),
	)
	if ret == 0 {
		if callErr == errNoMoreItems {
			return nil, nil // channel has no matching events
		}

		return nil, fmt.Errorf("EvtNext: %w", callErr)
	}

	if returned == 0 {
		return nil, nil
	}

	defer procEvtClose.Call(uintptr(eventHandle)) //nolint:errcheck

	return renderEventData(eventHandle)
}

// renderEventData renders an event handle as XML and returns its EventData fields.
func renderEventData(eventHandle windows.Handle) (map[string]string, error) {
	buf := make([]uint16, 8192)

	var bufUsed, propCount uint32

	for {
		ret, _, callErr := procEvtRender.Call(
			0, // NULL context for XML rendering
			uintptr(eventHandle),
			uintptr(evtRenderEventXml),
			uintptr(len(buf)*2),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&bufUsed)),
			uintptr(unsafe.Pointer(&propCount)),
		)

		if ret != 0 {
			break
		}

		if bufUsed > uint32(len(buf)*2) {
			// Buffer too small — grow to the size Windows told us we need.
			buf = make([]uint16, bufUsed/2+1)

			continue
		}

		return nil, fmt.Errorf("EvtRender: %w", callErr)
	}

	return ParseEventXML(windows.UTF16ToString(buf))
	return ParseEventDataXML([]byte(windows.UTF16ToString(buf)))
}

// ParseEventDataXML extracts EventData Name-to-value pairs from rendered event XML.
func ParseEventDataXML(data []byte) (map[string]string, error) {
	var ev eventXML
	if err := xml.Unmarshal(data, &ev); err != nil {
		return nil, fmt.Errorf("parse event XML: %w", err)
	}

	fields := make(map[string]string, len(ev.EventData.Data))

	for _, eventData := range ev.EventData.Data {
		fields[eventData.Name] = eventData.Value
	}

	return fields, nil
}
