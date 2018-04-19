package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	pto3 "github.com/mami-project/pto3-go"
	trace "github.com/mami-project/pto3-trace"
)

type nameValue struct {
	Name  string `json:"n"`
	Value string `json:"v"`
}

type tbHop struct {
	Address       string      `json:"ha"`
	TTL           int         `json:"t"`
	ICMPQuotation int         `json:"i"`
	Modifications []nameValue `json:"m"`
	Additions     []nameValue `json:"a"`
	Deletions     []nameValue `json:"d"`
}

type tbObs struct {
	Dst       string   `json:"dst"`
	Reason    string   `json:"r"`
	Timestamp int64    `json:"s"`
	Hops      []*tbHop `json:"h"`
}

const (
	tcpMD5SignatureOptionName   = "TCP::O::MD5SignatureOption"
	tcpAuthenticationOptionName = "TCP::O::TCPAuthenticationOption"
	tcpMSSOptionName            = "TCP::O::MSS"
)

func containsKey(nv []nameValue, key string) (bool, string) {
	for _, v := range nv {
		if v.Name == key {
			return true, v.Value
		}
	}
	return false, ""
}

func hasKeyAdded(hop *tbHop, key string) (bool, string) {
	if c, v := containsKey(hop.Additions, key); c {
		return true, v
	}
	return false, ""
}

func hasKeyDeleted(hop *tbHop, key string) bool {
	if c, _ := containsKey(hop.Deletions, key); c {
		return true
	}
	return false
}

func hasKeyModified(hop *tbHop, key string) (bool, string) {
	if c, v := containsKey(hop.Modifications, key); c {
		return c, v
	}
	return false, ""
}

func hasOption(hop *tbHop, name string) (bool, string) {
	if c, v := hasKeyAdded(hop, name); c {
		return c, v
	}
	if hasKeyDeleted(hop, name) {
		return true, ""
	}
	if c, v := hasKeyModified(hop, name); c {
		return c, v
	}
	return false, ""
}

func hasMD5SignatureOption(hop *tbHop) (bool, string) {
	return hasOption(hop, tcpMD5SignatureOptionName)
}

func hasAuthenticationOption(hop *tbHop) (bool, string) {
	return hasOption(hop, tcpAuthenticationOptionName)
}

func hasMSSChanged(hop *tbHop) (bool, string) {
	return hasKeyModified(hop, tcpMSSOptionName)
}

func makeTbObs(start *time.Time, path *pto3.Path,
	condition *pto3.Condition, value string) pto3.Observation {
	var ret pto3.Observation

	ret.TimeStart = start
	ret.TimeEnd = start
	ret.Path = path
	ret.Condition = condition
	ret.Value = value

	return ret
}

var condCache = make(map[string]*pto3.Condition)

func makeCondition(name string) *pto3.Condition {
	if val, ok := condCache[name]; ok {
		return val
	}

	ret := &pto3.Condition{Name: name}
	condCache[name] = ret

	return ret
}

func isTimedOut(tbobs *tbObs) bool {
	return tbobs.Reason == "timeouted" // sic!
}

func makeChange(old, new string) string {
	return fmt.Sprintf("{\"old\":\"%s\",\"new\":\"%s\"}", old, new)
}

func appendObservation(o []pto3.Observation, start *time.Time, path *pto3.Path, cname string, old, new string) []pto3.Observation {
	return append(o, makeTbObs(start, path, makeCondition(cname), makeChange(old, new)))
}

func extractTraceboxV1Observations(srcIP string, tcpDestPort string, line []byte) ([]pto3.Observation, error) {
	var tbobs tbObs
	var ret = make([]pto3.Observation, 0)

	if err := json.Unmarshal(line, &tbobs); err != nil {
		return nil, err
	}

	start := time.Unix(tbobs.Timestamp, 0)

	var md5Value string
	var authValue string

	for i, h := range tbobs.Hops {
		var path *pto3.Path

		if has, value := hasMD5SignatureOption(h); has {
			path = makePathForChange(path, srcIP, &tbobs, i)
			ret = appendObservation(ret, &start, path, "tcp.md5signature.changed", md5Value, value)
			md5Value = value
		}
		if has, value := hasAuthenticationOption(h); has {
			path = makePathForChange(path, srcIP, &tbobs, i)
			ret = appendObservation(ret, &start, path, "tcp.authentication.changed", authValue, value)
			authValue = value
		}
	}

	if len(tbobs.Hops) > 0 {
		// According to the standard, MSS can only change on the last hop.
		// TODO: should we check (and report) potentially erroneous changes
		// of MSS in between?
		path := makeFullPath(srcIP, &tbobs)
		if has, value := hasMSSChanged(tbobs.Hops[len(tbobs.Hops)-1]); has {
			ret = appendObservation(ret, &start, path, "tcp.mss.changed", "", value)
		}
	}

	return ret, nil
}

func normalizeTrace(rawBytes []byte, metain io.Reader, out io.Writer) error {
	md, err := pto3.RawMetadataFromReader(metain, nil)
	if err != nil {
		return fmt.Errorf("could not read metadata: %v", err)
	}

	var srcIP = md.Get("src_ip", true)
	var tcpDestPort = md.Get("tcp_dst_port", true)
	var in = bytes.NewReader(rawBytes)
	var scanner *bufio.Scanner
	var extractFunc func(string, string, []byte) ([]pto3.Observation, error)

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
		line := trace.TrimSpace(scanner.Bytes())

		if line[0] != '{' {
			continue
		}

		obsen, err := extractFunc(srcIP, tcpDestPort, line)
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

	for k := range md.Metadata {
		mdout[k] = md.Metadata[k]
	}

	for k := range conditions {
		mdcond = append(mdcond, k)
	}
	mdout["_conditions"] = mdcond

	mdout["_owner"] = md.Owner(true)
	mdout["_time_start"] = md.TimeStart(true).Format(time.RFC3339)
	mdout["_time_end"] = md.TimeEnd(true).Format(time.RFC3339)

	// hardcode analyzer path (FIXME, tag?)
	mdout["_analyzer"] = "https://github.com/mami-project/pto3-trace/tree/master/cmd/pto3-trace/pto3-trace.json"

	bytes, err := json.Marshal(mdout)
	if err != nil {
		return fmt.Errorf("error marshaling metadata: %s", err.Error())
	}

	if _, err := fmt.Fprintf(out, "%s\n", bytes); err != nil {
		return fmt.Errorf("error writing metadata: %s", err.Error())
	}

	return nil
}

func main() {
	mdfile := os.NewFile(3, ".piped_metadata.json")

	bytes, _, err := trace.MapFile(os.Stdin)
	if err != nil {
		log.Fatalf("can't map stdin: %v", err)
	}

	if err := normalizeTrace(bytes, mdfile, os.Stdout); err != nil {
		log.Fatalf("error while normalising: %v", err)
	}

	if err := trace.UnmapFile(bytes); err != nil {
		log.Fatalf("can't unmap stdin: %v", err)
	}
}
