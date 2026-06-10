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

package wevtapi

import (
	"encoding/xml"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	EvtQueryChannelPath      uint32 = 0x00000001
	EvtQueryReverseDirection uint32 = 0x00000200
	EvtRenderEventXml        uint32 = 1

	// ERROR_NO_MORE_ITEMS is returned by EvtNext when there are no more events.
	errorNoMoreItems = windows.Errno(259)
)

//nolint:gochecknoglobals
var (
	modWevtapi    = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery  = modWevtapi.NewProc("EvtQuery")
	procEvtNext   = modWevtapi.NewProc("EvtNext")
	procEvtRender = modWevtapi.NewProc("EvtRender")
	procEvtClose  = modWevtapi.NewProc("EvtClose")
)

// eventDataXML is a minimal representation of a Windows Event Log event XML envelope.
type eventDataXML struct {
	XMLName   xml.Name `xml:"Event"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// QueryLatestEventData queries a Windows Event Log channel for the most recent
// event matching the XPath query and returns EventData Name→Value pairs.
// Returns nil, nil when no matching events exist in the channel.
func QueryLatestEventData(channel, query string) (map[string]string, error) {
	channelPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return nil, fmt.Errorf("convert channel name: %w", err)
	}

	queryPtr, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return nil, fmt.Errorf("convert query string: %w", err)
	}

	queryHandle, _, callErr := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(channelPtr)),
		uintptr(unsafe.Pointer(queryPtr)),
		uintptr(EvtQueryChannelPath|EvtQueryReverseDirection),
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
		2000,
		0,
		uintptr(unsafe.Pointer(&returned)),
	)
	if ret == 0 {
		if callErr == errorNoMoreItems {
			return nil, nil
		}

		return nil, fmt.Errorf("EvtNext: %w", callErr)
	}

	if returned == 0 {
		return nil, nil
	}

	defer procEvtClose.Call(uintptr(eventHandle)) //nolint:errcheck

	buf := make([]uint16, 8192)

	var bufUsed, propCount uint32

	for {
		ret, _, callErr = procEvtRender.Call(
			0,
			uintptr(eventHandle),
			uintptr(EvtRenderEventXml),
			uintptr(len(buf)*2),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&bufUsed)),
			uintptr(unsafe.Pointer(&propCount)),
		)
		if ret != 0 {
			break
		}

		if bufUsed > uint32(len(buf)*2) {
			buf = make([]uint16, bufUsed/2+1)

			continue
		}

		return nil, fmt.Errorf("EvtRender: %w", callErr)
	}

	xmlStr := windows.UTF16ToString(buf)

	var ev eventDataXML
	if xmlErr := xml.Unmarshal([]byte(xmlStr), &ev); xmlErr != nil {
		return nil, fmt.Errorf("parse event XML: %w", xmlErr)
	}

	result := make(map[string]string, len(ev.EventData.Data))

	for _, d := range ev.EventData.Data {
		result[d.Name] = d.Value
	}

	return result, nil
}
