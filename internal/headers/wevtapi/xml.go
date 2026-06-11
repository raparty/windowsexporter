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

package wevtapi

import (
	"encoding/xml"
	"fmt"
)

// eventXML is a minimal representation of a Windows Event Log XML envelope,
// used only to extract EventData Name→Value pairs.
type eventXML struct {
	XMLName   xml.Name `xml:"Event"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// ParseEventXML parses a Windows Event Log XML string and returns its
// EventData fields as a Name→Value map. This is the pure-Go counterpart to
// renderEventData, usable without a live Windows event handle.
func ParseEventXML(rawXML string) (map[string]string, error) {
	var ev eventXML
	if err := xml.Unmarshal([]byte(rawXML), &ev); err != nil {
		return nil, fmt.Errorf("parse event XML: %w", err)
	}

	fields := make(map[string]string, len(ev.EventData.Data))

	for _, d := range ev.EventData.Data {
		fields[d.Name] = d.Value
	}

	return fields, nil
}
