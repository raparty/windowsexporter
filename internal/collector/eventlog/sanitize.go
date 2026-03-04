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

package eventlog

import "strings"

// sanitizeFaultingApplication extracts just the application name from the raw
// insertion string. The value may contain a full path or multi-line content
// (e.g. a stack trace); only the base filename of the first line is returned.
func sanitizeFaultingApplication(s string) string {
	// Take only the first line in case the string contains a stack trace.
	if idx := strings.IndexByte(s, '\n'); idx != -1 {
		s = s[:idx]
	}

	s = strings.TrimRight(s, "\r")

	// Extract just the filename from a full path (e.g. "C:\Windows\app.exe").
	if idx := strings.LastIndexAny(s, `/\`); idx != -1 {
		s = s[idx+1:]
	}

	return strings.TrimSpace(s)
}
