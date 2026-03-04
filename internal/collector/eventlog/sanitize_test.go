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

import (
	"strings"
	"testing"
)

func TestSanitizeFaultingApplication(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple exe name",
			input: "myapp.exe",
			want:  "myapp.exe",
		},
		{
			name:  "windows absolute path",
			input: `C:\Windows\System32\myapp.exe`,
			want:  "myapp.exe",
		},
		{
			name:  "forward slash path",
			input: "usr/local/bin/myapp",
			want:  "myapp",
		},
		{
			name:  "multiline stack trace",
			input: "myapp.exe\nStack trace:\n  at foo()\n  at bar()",
			want:  "myapp.exe",
		},
		{
			name:  "windows path with CRLF",
			input: "C:\\apps\\myapp.exe\r\nmore content",
			want:  "myapp.exe",
		},
		{
			name:  "trailing whitespace",
			input: "myapp.exe   ",
			want:  "myapp.exe",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "path with trailing separator",
			input: `C:\Windows\`,
			want:  "",
		},
		{
			name:  "name exceeding max label length is truncated",
			input: strings.Repeat("a", maxLabelLength+10),
			want:  strings.Repeat("a", maxLabelLength),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := sanitizeFaultingApplication(tc.input)
			if got != tc.want {
				t.Errorf("sanitizeFaultingApplication(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
