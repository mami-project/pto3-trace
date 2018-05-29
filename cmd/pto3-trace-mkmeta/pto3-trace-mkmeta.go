// Copyright 2018 Zurich University of Applied Sciences.
// All rights reserved. Use of this source code is governed
// by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	pto3 "github.com/mami-project/pto3-go"
	trace "github.com/mami-project/pto3-trace"
)

type campaignMeta struct {
	FileType string `json:"_file_type"`
	Owner    string `json:"_owner"`

	// The value we assume for the TCP flags. Tracebox measures
	// changes to the flags, but doesn't say what the flags were
	// changed from.
	TCPFlags string `json:"presumed_tcp_flags"`

	// The value for the timezone in which the measurements are taken.
	// Tracebox does not record the time zone. The timezone can be either
	// an official timezone, such as "GMT+2", "CEST", or "UTC", or an
	// assumed timezone, which takes the form "ProbablyTZ", e.g.,
	// "ProbablyGMT+2", "ProbablyCEST", "ProbablyUTC".
	Timezone string `json:"timezone"`
}

type fileMeta struct {
	//campaignMeta        // For consolidation. Leave empty if not consolidating
	Vantage string `json:"src_ip"`
	Port    int    `json:"tcp_dst_port"`
	Start   string `json:"_time_start"`
	End     string `json:"_time_end"`
}

var (
	campaign    = flag.Bool("with-campaign", false, "also write campaign metadata")
	consolidate = flag.Bool("consolidate", false, "consolidate campaign and file metadata into single file (useful for debugging)")
	filetype    = flag.String("filetype", "tracebox-v1-ndjson", "file type of individual files")
	logfileName = flag.String("logfile", "", "log file to use (default os.Stderr)")
	owner       = flag.String("owner", "", "owner of the raw data")
	tcpFlags    = flag.String("tcp-flags", "0x2", "presumed TCP flags for this tracebox campaign")
	timezone    = flag.String("timezone", "ProbablyUTC", "timezone for time stamps")
)

var logger *log.Logger

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "%s, git ref %s\n", os.Args[0], trace.CommitRef)
	flag.PrintDefaults()
}

func writeJSON(object interface{}, out io.Writer) error {
	bytes, err := json.Marshal(object)
	if err != nil {
		logger.Printf("ERROR: can't marshal campaign metadata: %v", err)
		return err
	}

	n, err := out.Write(bytes)
	if err != nil {
		logger.Printf("ERROR: can't write campaign metadata to \"%s\": %v",
			pto3.CampaignMetadataFilename, err)
		return err
	}

	if n != len(bytes) {
		logger.Printf("ERROR: expected to write %d bytes, but wrote only %d", len(bytes), n)
		return err
	}

	return nil
}

func writeCampaignMeta() {
	if *owner == "" {
		// Write this to the normal logging output, not the logger.
		log.Fatal("FATAL: must set owner with \"-owner\" flag")
	}

	f, err := os.Create(pto3.CampaignMetadataFilename)
	if err != nil {
		logger.Fatalf("can't open metadata file \"%s\": %v", pto3.CampaignMetadataFilename, err)
	}

	var cm = campaignMeta{
		FileType: *filetype,
		Owner:    *owner,
		TCPFlags: *tcpFlags,
		Timezone: *timezone,
	}

	var mustRm = false
	if writeJSON(cm, f) != nil {
		logger.Printf("WARNING: error writing JSON for campaign metadata, not written")
		mustRm = true
	}

	if err := f.Close(); err != nil {
		logger.Printf("WARNING: can't close campaign metadata file: %v", err)
	}

	if mustRm {
		if err := os.Remove(pto3.CampaignMetadataFilename); err != nil {
			logger.Printf("WARNING: can't remove campaign metadata file: %v", err)
		}
	}

	if mustRm {
		os.Exit(1)
	}
}

var tbNameRe = regexp.MustCompile(`(\d+)-(\d+)-(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.json`)
var timestampRe = regexp.MustCompile(`"s":(\d+)`)

func writeFileMeta(path string) {
	fname := filepath.Base(path)

	matches := tbNameRe.FindStringSubmatch(fname)
	if matches == nil {
		logger.Printf("ERROR: file name \"%s\" does not have expected form, skipping", fname)
		return
	}

	sport := matches[1]
	port, err := strconv.ParseInt(sport, 10, 32)
	if err != nil {
		logger.Panicf("can't happen: number \"%s\" doesn't match number regexp", matches[1])
	}
	vantage := fmt.Sprintf("%s.%s.%s.%s", matches[3], matches[4], matches[5], matches[6])

	f, err := os.Open(path)
	if err != nil {
		logger.Printf("ERROR: skipping file \"%s\": %v", path, err)
		return
	}

	scanner := bufio.NewScanner(f)

	var minSec int64 = math.MaxInt64
	var maxSec int64
	var lineno int

	for scanner.Scan() {
		lineno++
		line := strings.TrimSpace(scanner.Text())
		matches := timestampRe.FindStringSubmatch(line)
		if matches == nil {
			logger.Printf("WARNING: %s:%d: record without timestamp", path, lineno)
		}

		s, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			logger.Panicf("can't happen: number \"%s\" doesn't match number regexp", matches[1])
		}

		if s < minSec {
			minSec = s
		}
		if s > maxSec {
			maxSec = s
		}
	}

	if err := f.Close(); err != nil {
		logger.Printf("WARNING: error closing \"%s\": %v", path, err)
	}

	md := fileMeta{
		Vantage: vantage,
		Port:    int(port),
		Start:   time.Unix(minSec, 0).UTC().Format(time.RFC3339),
		End:     time.Unix(maxSec, 0).UTC().Format(time.RFC3339),
	}

	//if *consolidate {
	//	md.FileType = *filetype
	//	md.Owner = *owner
	//}

	mname := fmt.Sprintf("%s%s", fname, pto3.FileMetadataSuffix)
	mdout, err := os.Create(mname)
	if err != nil {
		logger.Printf("ERROR: can't open metadata file \"%s\" for writing: %v", mname, err)
		return
	}

	var mustRm bool
	var hasErr bool
	if writeJSON(md, mdout) != nil {
		logger.Printf("WARNING: error writing metadata \"%s\" for tracebox file \"%s\", removing", mname, path)
		mustRm = true
		hasErr = true
	}

	if err := mdout.Close(); err != nil {
		logger.Printf("WARNING: can't close metadata \"%s\" for tracebox file \"%s\": %v", mname, path, err)
		hasErr = true
	}

	if mustRm {
		if err := os.Remove(mname); err != nil {
			logger.Printf("WARNING: can't remove metadata \"%s\" for tracebox file \"%s\": %v", mname, path, err)
			hasErr = true
		}
	}

	if hasErr {
		logger.Printf("INFO: tracebox file \"%s\" processed with errors or warnings", path)
	} else {
		logger.Printf("INFO: tracebox file \"%s\" processed successfully", path)
	}
}

func writeFilesMeta(paths []string) {
	for _, p := range paths {
		fi, err := os.Stat(p)

		if err != nil {
			logger.Printf("WARNING: Can't stat \"%s\"", p)
			continue
		}

		mode := fi.Mode()

		if mode.IsDir() {
			// recurse

			files, err := ioutil.ReadDir(p)

			if err != nil {
				logger.Printf("WARNING: Can't read directory \"%s\"", p)
				continue
			}

			paths := make([]string, len(files))

			for i, f := range files {
				paths[i] = filepath.Join(p, f.Name())
			}

			writeFilesMeta(paths)
		} else {
			writeFileMeta(p)
		}
	}
}

func initLogging() {
	var logfile io.Writer

	if *logfileName != "" {
		var err error
		logfile, err = os.Create(*logfileName)
		if err != nil {
			log.Fatalf("can't open log file \"%s\": %v", *logfileName, err)
		}
	} else {
		logfile = os.Stderr
	}

	logger = log.New(logfile, "", log.LstdFlags|log.LUTC)
	logger.Printf("INFO: all timestamps in this log are UTC")
}

func main() {
	flag.Usage = usage
	flag.Parse()

	initLogging()

	if *campaign {
		writeCampaignMeta()
	}

	writeFilesMeta(flag.Args())

	if *logfileName != "" {
		fmt.Printf("see log file \"%s\" for details\n", *logfileName)
	}
}
