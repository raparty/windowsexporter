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

// Package bootperformance exposes Windows boot-performance metrics derived
// from the Microsoft-Windows-Diagnostics-Performance/Operational event log.
// The most recent Boot Performance Measurement event (ID 100) is queried on
// every scrape via EvtQuery / EvtNext / EvtRender from wevtapi.dll and the
// four timing fields are emitted as gauges.
package bootperformance

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus-community/windows_exporter/internal/headers/wevtapi"
	"github.com/prometheus-community/windows_exporter/internal/mi"
	"github.com/prometheus-community/windows_exporter/internal/types"
	"github.com/prometheus/client_golang/prometheus"
)

// Name is the collector identifier used for registration and the
// --collectors.enabled flag.
const Name = "bootperformance"

// diagnosticsChannel is the ETW/EVTX channel written by the
// Microsoft-Windows-Diagnostics-Performance provider.
const diagnosticsChannel = "Microsoft-Windows-Diagnostics-Performance/Operational"

// bootPerfXPath selects only Boot Performance Measurement events.
const bootPerfXPath = "*[System[EventID=100]]"

// Config holds collector configuration. No flags are currently exposed.
type Config struct{}

//nolint:gochecknoglobals
var ConfigDefaults = Config{}

// Collector implements the bootperformance Prometheus collector.
type Collector struct {
	config Config
	logger *slog.Logger

	bootTimeMs          *prometheus.Desc
	mainPathBootTimeMs  *prometheus.Desc
	postBootTimeMs      *prometheus.Desc
	bootStartupApps     *prometheus.Desc
}

func New(config *Config) *Collector {
	if config == nil {
		config = &ConfigDefaults
	}

	return &Collector{config: *config}
}

func NewWithFlags(_ *kingpin.Application) *Collector {
	return &Collector{}
}

func (c *Collector) GetName() string { return Name }

func (c *Collector) Close() error { return nil }

// Build initialises the Prometheus metric descriptors.
// miSession is accepted to satisfy the Collector interface but is not used.
func (c *Collector) Build(logger *slog.Logger, _ *mi.Session) error {
	c.logger = logger.With(slog.String("collector", Name))

	c.bootTimeMs = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "boot_time_ms"),
		"Total boot duration in milliseconds "+
			"(Microsoft-Windows-Diagnostics-Performance/Operational Event 100, field BootTime).",
		nil, nil,
	)
	c.mainPathBootTimeMs = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "mainpath_boot_time_ms"),
		"Main boot path duration in milliseconds "+
			"(Microsoft-Windows-Diagnostics-Performance/Operational Event 100, field MainPathBootTime).",
		nil, nil,
	)
	c.postBootTimeMs = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "post_boot_time_ms"),
		"Post-boot phase duration in milliseconds "+
			"(Microsoft-Windows-Diagnostics-Performance/Operational Event 100, field BootPostBootTime).",
		nil, nil,
	)
	c.bootStartupApps = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, "", "boot_startup_apps"),
		"Number of startup applications that ran during the last boot "+
			"(Microsoft-Windows-Diagnostics-Performance/Operational Event 100, field BootNumStartupApps).",
		nil, nil,
	)

	return nil
}

// Collect queries the most recent Diagnostics-Performance Boot event and emits
// the three boot-timing gauges. If no event exists the metrics are omitted
// rather than emitting zero, so stale data is never presented.
func (c *Collector) Collect(ch chan<- prometheus.Metric) error {
	fields, err := wevtapi.QueryLatestEventData(diagnosticsChannel, bootPerfXPath)
	if err != nil {
		return fmt.Errorf("query %s: %w", diagnosticsChannel, err)
	}

	if fields == nil {
		// The Diagnostics-Performance log is empty or the channel is not
		// available on this system (e.g. stripped/server SKUs). Skip silently.
		c.logger.Debug("no boot performance event found; skipping boot metrics")

		return nil
	}

	emitGauge := func(desc *prometheus.Desc, fieldName string) {
		raw, ok := fields[fieldName]
		if !ok {
			c.logger.Debug("boot event field absent", slog.String("field", fieldName))

			return
		}

		val, parseErr := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if parseErr != nil {
			c.logger.Warn("unparseable boot event field",
				slog.String("field", fieldName),
				slog.String("raw", raw),
				slog.Any("err", parseErr),
			)

			return
		}

		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, val)
	}

	emitGauge(c.bootTimeMs, "BootTime")
	emitGauge(c.mainPathBootTimeMs, "MainPathBootTime")
	emitGauge(c.postBootTimeMs, "BootPostBootTime")
	emitGauge(c.bootStartupApps, "BootNumStartupApps")

	return nil
}
