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
	"testing"

	"github.com/prometheus-community/windows_exporter/internal/headers/wevtapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBootPerformanceValues(t *testing.T) {
	t.Parallel()

	const eventXML = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Diagnostics-Performance"/>
    <EventID>100</EventID>
  </System>
  <EventData>
    <Data Name="BootTime">133626</Data>
    <Data Name="MainPathBootTime">54726</Data>
    <Data Name="BootPostBootTime">78900</Data>
    <Data Name="BootNumStartupApps">13</Data>
    <Data Name="BootDriverInitTime">8537</Data>
    <Data Name="BootUserProfileProcessingTime">2371</Data>
  </EventData>
</Event>`

	fields, err := wevtapi.ParseEventXML(eventXML)
	require.NoError(t, err)

	values, parseErrors := parseBootPerformanceValues(fields)
	require.Empty(t, parseErrors)

	require.NotNil(t, values.bootTime)
	assert.InDelta(t, 133626, *values.bootTime, 0)

	require.NotNil(t, values.mainPathBootTime)
	assert.InDelta(t, 54726, *values.mainPathBootTime, 0)

	require.NotNil(t, values.postBootTime)
	assert.InDelta(t, 78900, *values.postBootTime, 0)

	require.NotNil(t, values.startupApps)
	assert.InDelta(t, 13, *values.startupApps, 0)

	require.NotNil(t, values.driverInitTime)
	assert.InDelta(t, 8537, *values.driverInitTime, 0)

	require.NotNil(t, values.userProfileTime)
	assert.InDelta(t, 2371, *values.userProfileTime, 0)
}

func TestParseBootPerformanceValuesOmitsInvalidFields(t *testing.T) {
	t.Parallel()

	values, parseErrors := parseBootPerformanceValues(map[string]string{
		"BootTime":           "not-a-number",
		"MainPathBootTime":   "54726",
		"BootNumStartupApps": "13",
	})

	assert.Nil(t, values.bootTime)
	assert.Nil(t, values.postBootTime)
	require.NotNil(t, values.mainPathBootTime)
	require.NotNil(t, values.startupApps)
	assert.Contains(t, parseErrors, "BootTime")
}

func TestParseBootPerformanceValuesRetainsZero(t *testing.T) {
	t.Parallel()

	values, parseErrors := parseBootPerformanceValues(map[string]string{
		"BootDriverInitTime":              "0",
		"BootUserProfileProcessingTime":   "0",
	})
	require.Empty(t, parseErrors)

	require.NotNil(t, values.driverInitTime)
	assert.InDelta(t, 0, *values.driverInitTime, 0)

	require.NotNil(t, values.userProfileTime)
	assert.InDelta(t, 0, *values.userProfileTime, 0)
}
