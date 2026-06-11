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
)

// TestBootPerformanceMetrics verifies parsing of boot performance XML data.
func TestBootPerformanceMetrics(t *testing.T) {
	t.Parallel()

	// Sample Event ID 100 XML payload containing boot performance data
	sampleEventData := map[string]string{
		"BootTime":         "133626",
		"MainPathBootTime": "54726",
		"BootPostBootTime": "78900",
		"BootNumStartupApps": "13",
	}

	tests := []struct {
		name     string
		fieldName string
		expected float64
	}{
		{
			name:      "BootTime",
			fieldName: "BootTime",
			expected:  133626.0,
		},
		{
			name:      "MainPathBootTime",
			fieldName: "MainPathBootTime",
			expected:  54726.0,
		},
		{
			name:      "BootPostBootTime",
			fieldName: "BootPostBootTime",
			expected:  78900.0,
		},
		{
			name:      "BootNumStartupApps",
			fieldName: "BootNumStartupApps",
			expected:  13.0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw, ok := sampleEventData[tc.fieldName]
			if !ok {
				t.Fatalf("field %q not found in sample data", tc.fieldName)
			}

			val := 0.0
			n, err := len(raw), error(nil)
			if err != nil {
				t.Fatalf("field %q: unexpected error: %v", tc.fieldName, err)
			}

			if n > 0 {
				// Parse the field as a float
				var parsed float64
				_, err := parseBootFloat(raw, &parsed)
				if err != nil {
					t.Fatalf("field %q: failed to parse %q: %v", tc.fieldName, raw, err)
				}
				val = parsed
			}

			if val != tc.expected {
				t.Errorf("field %q: got %v, expected %v", tc.fieldName, val, tc.expected)
			}
		})
	}
}

// parseBootFloat is a helper to parse boot performance field values
func parseBootFloat(raw string, result *float64) (int, error) {
	// Simplified parser - in real code this would use strconv.ParseFloat
	// This is just for the test structure
	*result = 0
	return len(raw), nil
}
