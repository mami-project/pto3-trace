// mkjson takes a tracebox file, extracts metadata information from it, and
// then writes that metadata to stdout.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mami-project/pto3-go"
)

type campaignMeta struct {
	FileType string `json:"_file_type"`
	Owner    string `json:"_owner"`
}

type fileMeta struct {
	Vantage string `json:"vantage"`
	Port    int    `json:"port"`
	Start   string `json:"_time_start"`
	End     string `json:"_time_end"`
}

var (
	owner    = flag.String("owner", "", "owner of the raw data")
	campaign = flag.Bool("with-campaign", false, "also ˘write campaign metadata")
	filetype = flag.String("filetype", "tracebox-v1-ndjson", "file type of individual files")
)

func mustWriteJSON(object interface{}, out io.Writer) {
	bytes, err := json.Marshal(object)
	if err != nil {
		log.Fatalf("can't marshal campaign metadata: %v", err)
	}

	n, err := out.Write(bytes)
	if err != nil {
		log.Fatalf("can't write campaign metadata to \"%s\": %v", pto3.CampaignMetadataFilename, err)
	}

	if n != len(bytes) {
		log.Fatalf("campaign metadata: expected to write %d bytes, but wrote only %d", len(bytes), n)
	}
}

func writeCampaignMeta() {
	if *owner == "" {
		log.Fatal("must set owner with \"-owner\" flag")
	}

	f, err := os.Create(pto3.CampaignMetadataFilename)
	if err != nil {
		log.Fatalf("can't open metadata file \"%s\": %v", pto3.CampaignMetadataFilename, err)
	}

	var cm = campaignMeta{
		FileType: *filetype,
		Owner:    *owner,
	}

	mustWriteJSON(cm, f)
}

var tbNameRe = regexp.MustCompile(`(\d+)-(\d+)-(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.json`)
var timestampRe = regexp.MustCompile(`"s":(\d+)`)

func writeFileMeta(path string) {
	fname := filepath.Base(path)

	matches := tbNameRe.FindStringSubmatch(fname)
	if matches == nil {
		log.Fatalf("file name \"%s\" does not have expected form, e.g., \"80-00-129.22.123.12.json\"", fname)
	}

	sport := matches[1]
	port, err := strconv.ParseInt(sport, 10, 32)
	if err != nil {
		log.Panicf("can't happen: number \"%s\" doesn't match number regexp", matches[1])
	}
	try := matches[2]
	vantage := fmt.Sprintf("%s.%s.%s.%s", matches[3], matches[4], matches[5], matches[6])

	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("can't open file \"%s\" for reading: %v", path, err)
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
			log.Fatalf("%s:%d: record without timestamp", path, lineno)
		}

		s, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			log.Panicf("can't happen: number \"%s\" doesn't match number regexp", matches[1])
		}

		if s < minSec {
			minSec = s
		}
		if s > maxSec {
			maxSec = s
		}
	}

	md := fileMeta{
		Vantage: vantage,
		Port:    int(port),
		Start:   time.Unix(minSec, 0).UTC().Format(time.RFC3339),
		End:     time.Unix(maxSec, 0).UTC().Format(time.RFC3339),
	}

	dir := filepath.Dir(path)
	mname := fmt.Sprintf("%s/%s-%s-%s%s", dir, sport, try, vantage, pto3.FileMetadataSuffix)
	mdout, err := os.Create(mname)
	if err != nil {
		log.Fatalf("can't open metadata file \"%s\" for writing: %v", mname, err)
	}

	mustWriteJSON(md, mdout)

	if err := mdout.Close(); err != nil {
		log.Fatalf("can't close metadata file \"%s\": %v", mname, err)
	}
}

func main() {
	flag.Parse()

	if *campaign {
		writeCampaignMeta()
	}
	writeFileMeta(flag.Arg(0))
}
