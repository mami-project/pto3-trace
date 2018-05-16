package main

//go:generate perl extract-conditions.pl pto3-trace.go conditions.go

//go:generate perl gitref.pl gitref.go

/*
   The following conditions were extracted from the tracebox files. On the left
   is the count how often the condition was observed, then comes  the condition
   name as it appears in the tracebox files.

   On the right is the decision what we decided to do with the condition.

   * Ignore means the condition is ignored, either because it is so numerous
	 as to be meaningless or so rare that it's not clear what the precise
	 semantics are. Another reason is that the condition represents something
	 that the *endpoint* did, in which case we're not interested. (We're only
	 interested in what britram refers to as "middlebox fuckery".)
   * tcp.<cond>.changed means that the condition is processed and turned into
	 the relevant PTO condition.
   * Nothing. In this case, it's not clear what to do with the tracebox condition,
	 for example because it's not clear whether it represents middlebox fuckery
	 (see above) or whether it's something that a reasonable
	 middlebox may well add or change.

   The format of the table below is crucial, since it is being automatically
   processed by extract-conditions.pl. So you can't remove this table, only
   change the Decision column.

  Count     | Name                           | Decision
  ==========+================================+=====================
  9171447313 IP::Checksum                    | Ignore
  9171446541 IP::TTL                         | Ignore
  1279130958 IP::DiffServicesCP              | Ignore
   326560370 TCP::O::MSS                     | tcp.mss.changed
   260492548 TCP::Checksum                   | Ignore
   172780786 TCP::SeqNumber                  | Ignore
    21264366 TCP::O::SACKPermitted           | NEW tcp.sack-permitted.changed
     5460040 IP::Length                      | NEW tcp.length.changed
     1960762 TCP::Offset                     | NEW tcp.offset.changed
      489556 IP::ID                          | NEW tcp.id.changed
       75071 TCP::Window                     | NEW tcp.window.changed
       68811 TCP::O::WSOPT-WindowScale       | NEW tcp.wsopt-windows-scale.changed
       16568 TCP::O::TSOPT-TimeStampOption   | NEW tcp.tsopt-timestamp-option.changed
       14606 TCP::Flags                      | NEW tcp.flags.changed
       13120 IP::ECN                         | tcp.ecn.changed
        9644 TCP::SPort                      | NEW tcp.sport.changed
        8313 IP::Flags                       | NEW ip.flags.changed
        5797 TCP::AckNumber                  | NEW tcp.ack-number.changed
        4646 TCP::UrgentPtr                  | NEW tcp.urgent-ptr.changed
        4143 TCP::Reserved                   | NEW tcp.reserved.changed
        3403 TCP::O::TCPAuthenticationOption | tcp.authentication-option.changed
        3172 TCP::O::Echo                    | NEW tcp.echo.changed
        3138 TCP::O::CC                      | NEW tcp.cc.changed
        2465 TCP::O::CC.ECHO                 | NEW tcp.cc-echo.changed
        1335 TCP::O::MD5SignatureOption      | tcp.md5-signature.changed
        1230 TCP::O::CC.NEW                  | NEW tcp.cc-new.changed
        1088 TCP::O::Quick-StartResponse     | NEW tcp.quick-startresponse.changed
        1055 TCP::O::EchoReply               | NEW tcp.echo-reply.changed
        1037 TCP::O::PartialOrderConnectionPermitted | NEW tcp.partial-order-connection-permitted.changed
        1028 TCP::O::TCPAlternateChecksumRequest | NEW tcp.alternate-checksum-request.changed
         940 TCP::O::SACK                    | NEW tcp.sack.changed
         903 TCP::O::SNAP                    | NEW tcp.snap.changed
         864 TCP::O::(null)                  | Ignore
         828 TCP::O::UserTimeoutOption       | NEW tcp.user-timeout-option.changed
         682 TCP::O::TrailerChecksumOption   | NEW tcp.trailer-checksum-option.changed
         677 TCP::O::SCPSCapabilities        | NEW tcp.scps-capabilities.changed
         660 TCP::O::TCPAlternateChecksumData | NEW tcp.alternate-checksum-data.changed
         647 TCP::O::PartialOrderServiceProfile | NEW tcp.partial-order-service-profile.changed
         587 TCP::O::SelectiveNegativeAck    | NEW tcp.selective-negative-ack.changed
         526 TCP::O::RecordBoundaries        | NEW tcp.record-boundaries.changed
         525 TCP::O::MultipathTCP            | NEW tcp.multipath-tcp.changed
         458 TCP::O::CorruptionExperienced   | NEW tcp.corruption-experienced.changed

*/
import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
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

func toHexString(s string) string {
	num, err := strconv.ParseInt(s, 16, 64)

	if err == nil {
		return fmt.Sprintf("0x%x", num)
	}
	return ""
}

func makeChange(new string) string {
	if numberString := toHexString(new); numberString != "" {
		return numberString
	}
	return new
}

func appendObservation(o []pto3.Observation, start *time.Time, path *pto3.Path, cname string, new string) []pto3.Observation {
	return append(o, makeTbObs(start, path, makeCondition(cname), makeChange(new)))
}

func extractTraceboxV1Observations(srcIP string, tcpDestPort string, line []byte) ([]pto3.Observation, error) {
	var tbobs tbObs

	if err := json.Unmarshal(line, &tbobs); err != nil {
		return nil, err
	}

	var ret = make([]pto3.Observation, 0)
	start := time.Unix(tbobs.Timestamp, 0)

	for i, h := range tbobs.Hops {
		var path *pto3.Path

		for _, m := range h.Modifications {
			if ptoCond, ok := tbToCond[m.Name]; ok {
				path = makePathForChange(path, srcIP, &tbobs, i)
				ret = appendObservation(ret, &start, path, ptoCond, m.Value)
			}
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
	mdout["_analyzer"] = "https://github.com/mami-project/pto3-trace/tree/" + commitRef + "/cmd/pto3-trace/pto3-trace.json"

	// state uncertainty about timestamp timezone, as per
	// conversation with britram. This value, "uncertain"
	// means that essentially anything goes, not even
	// timezones between measurements are required to be in
	// the same timezone. Later values may be more precise
	mdout["obs_tz"] = "uncertain"

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
