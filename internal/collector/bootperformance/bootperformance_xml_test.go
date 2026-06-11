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

package bootperformance_test

import (
	"testing"

	"github.com/prometheus-community/windows_exporter/internal/headers/wevtapi"
)

// sampleBootEvent100 is a representative Event ID 100 XML payload from the
// Microsoft-Windows-Diagnostics-Performance/Operational channel.
const sampleBootEvent100 = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Diagnostics-Performance"/>
    <EventID>100</EventID>
  </System>
  <EventData>
    <Data Name="BootTime">133626</Data>
    <Data Name="MainPathBootTime">54726</Data>
    <Data Name="BootPostBootTime">78900</Data>
    <Data Name="BootNumStartupApps">13</Data>
  </EventData>
</Event>`

func TestParseBootEvent100(t *testing.T) {
	t.Parallel()

	fields, err := wevtapi.ParseEventXML(sampleBootEvent100)
	if err != nil {
		t.Fatalf("ParseEventXML: %v", err)
	}

	want := map[string]string{
		"BootTime":           "133626",
		"MainPathBootTime":   "54726",
		"BootPostBootTime":   "78900",
		"BootNumStartupApps": "13",
	}

	for name, wantVal := range want {
		got, ok := fields[name]
		if !ok {
			t.Errorf("field %q missing from parsed output", name)

			continue
		}

		if got != wantVal {
			t.Errorf("field %q: got %q, want %q", name, got, wantVal)
		}
	}
}
