package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	pto3 "github.com/mami-project/pto3-go"
)

type nameValue struct {
	Name  string `json:"n"`
	Value string `json:"v"`
}

type traceboxObservation struct {
	Dst       string `json:"dst"`
	Reason    string `json:"r"`
	Timestamp int64  `json:"s"`
	Hops      []struct {
		Address       string      `json:"ha"`
		TTL           int         `json:"t"`
		I             int         `json:"i"`
		Modifications []nameValue `json:"m"`
		Additions     []nameValue `json:"a"`
		Deletions     []nameValue `json:"d"`
	} `json:"h"`
}

func extractTraceboxV1Observations(line string) ([]pto3.Observation, error) {
	//var tbobs traceboxObservation

	//if err := json.Unmarshal([]byte(line), &tbobs); err != nil {
	//	return nil, err
	//}

	//start := time.Unix(tbobs.Timestamp, 0)
	//path := new(pto3.Path)

	return nil, nil
}

func normalizeTrace(in io.Reader, metain io.Reader, out io.Writer) error {
	md, err := pto3.RawMetadataFromReader(metain, nil)
	if err != nil {
		return fmt.Errorf("could not read metadata: %v", err)
	}

	var scanner *bufio.Scanner
	var extractFunc func(string) ([]pto3.Observation, error)

	switch md.Filetype(true) {
	case "tracebox-v1-ndjson":
		scanner = bufio.NewScanner(in)
		extractFunc = extractTraceboxV1Observations
	default:
		return fmt.Errorf("unsupported filetype %s", md.Filetype(true))
	}

	conditions := make(map[string]bool)

	var lineno int
	for scanner.Scan() {
		lineno++
		line := strings.TrimSpace(scanner.Text())

		if line[0] != '{' {
			continue
		}

		obsen, err := extractFunc(line)
		if err != nil {
			return fmt.Errorf("error parsing tracebox data at line %d: %v", lineno, err)
		}

		for _, o := range obsen {
			conditions[o.Condition.Name] = true
		}

		if err := pto3.WriteObservations(obsen, out); err != nil {
			return fmt.Errorf("error writing observation from line %d: %s", lineno, err.Error())
		}
	}

	mdout := make(map[string]interface{})
	mdcond := make([]string, 0)

	// copy all aux metadata from the raw file
	for k := range md.Metadata {
		mdout[k] = md.Metadata[k]
	}

	// create condition list from observed conditions
	for k := range conditions {
		mdcond = append(mdcond, k)
	}
	mdout["_conditions"] = mdcond

	// add start and end time and owner, since we have it
	mdout["_owner"] = md.Owner(true)
	mdout["_time_start"] = md.TimeStart(true).Format(time.RFC3339)
	mdout["_time_end"] = md.TimeEnd(true).Format(time.RFC3339)

	// hardcode analyzer path (FIXME, tag?)
	mdout["_analyzer"] = "https://github.com/mami-project/pto3-trace/tree/master/pto3-trace.json"

	// serialize and write to stdout
	b, err := json.Marshal(mdout)
	if err != nil {
		return fmt.Errorf("error marshaling metadata: %s", err.Error())
	}

	if _, err := fmt.Fprintf(out, "%s\n", b); err != nil {
		return fmt.Errorf("error writing metadata: %s", err.Error())
	}

	return nil
}

func main() {
	// wrap a file around the metadata stream
	mdfile := os.NewFile(3, ".piped_metadata.json")

	if err := normalizeTrace(os.Stdin, mdfile, os.Stdout); err != nil {
		log.Fatal(err)
	}
}
