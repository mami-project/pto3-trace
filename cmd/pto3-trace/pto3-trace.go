// Copyright 2018 Zurich University of Applied Sciences.
// All rights reserved. Use of this source code is governed
// by a BSD-style license that can be found in the LICENSE file.

//go:generate perl extract-conditions.pl pto3-trace.go conditions.go

package main

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
  1279130958 IP::DiffServicesCP              | NEW dscp.0.changed
   326560370 TCP::O::MSS                     | tcp.option.mss.changed
   260492548 TCP::Checksum                   | Ignore
   172780786 TCP::SeqNumber                  | Ignore
    21264366 TCP::O::SACKPermitted           | NEW tcp.option.sackok.changed
     5460040 IP::Length                      | NEW tcp.length.changed
     1960762 TCP::Offset                     | NEW tcp.offset.changed
      489556 IP::ID                          | NEW ip4.id.changed
       75071 TCP::Window                     | NEW tcp.window.changed
       68811 TCP::O::WSOPT-WindowScale       | NEW tcp.option.ws.changed
       16568 TCP::O::TSOPT-TimeStampOption   | NEW tcp.option.ts.changed
       14606 TCP::Flags                      | NEW tcp.flags.changed
       13120 IP::ECN                         | ecn.ip.changed
        9644 TCP::SPort                      | NEW tcp.sport.changed
        8313 IP::Flags                       | NEW ip.flags.changed
        5797 TCP::AckNumber                  | NEW tcp.ack.changed
        4646 TCP::UrgentPtr                  | NEW tcp.urg.changed
        4143 TCP::Reserved                   | NEW tcp.reserved.changed
        3403 TCP::O::TCPAuthenticationOption | tcp.option.ao.changed
        3172 TCP::O::Echo                    | NEW tcp.option.rfc1072.echo.changed
        3138 TCP::O::CC                      | NEW tcp.option.rfc1644.cc.changed
        2465 TCP::O::CC.ECHO                 | NEW tcp.option.rfc1644.echo.changed
        1335 TCP::O::MD5SignatureOption      | tcp.option.md5.changed
        1230 TCP::O::CC.NEW                  | NEW tcp.option.rfc1644.new.changed
        1088 TCP::O::Quick-StartResponse     | NEW tcp.option.rfc4782.changed
        1055 TCP::O::EchoReply               | NEW tcp.option.rfc1072.reply.changed
        1037 TCP::O::PartialOrderConnectionPermitted | NEW tcp.option.rfc1693.permitted.changed
        1028 TCP::O::TCPAlternateChecksumRequest | NEW tcp.option.rfc1146.request.changed
         940 TCP::O::SACK                    | NEW tcp.option.sack.changed
         903 TCP::O::SNAP                    | NEW tcp.option.snap.changed
         864 TCP::O::(null)                  | Ignore
         828 TCP::O::UserTimeoutOption       | NEW tcp.option.user-timeout.changed
         682 TCP::O::TrailerChecksumOption   | NEW tcp.option.trailer-checksum.changed
         677 TCP::O::SCPSCapabilities        | NEW tcp.option.scps-capabilities.changed
         660 TCP::O::TCPAlternateChecksumData | NEW tcp.option.rfc1146.data.changed
         647 TCP::O::PartialOrderServiceProfile | NEW tcp.option.rfc1693.profile.changed
         587 TCP::O::SelectiveNegativeAck    | NEW tcp.option.selective-nack.changed
         526 TCP::O::RecordBoundaries        | NEW tcp.option.record-boundaries.changed
         525 TCP::O::MultipathTCP            | NEW tcp.option.mptcp.changed
         458 TCP::O::CorruptionExperienced   | NEW tcp.option.corruption-experienced.changed

*/
import (
	"bufio"
	"bytes"
	//"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"time"

	pto3 "github.com/mami-project/pto3-go"
	trace "github.com/mami-project/pto3-trace"

	"github.com/json-iterator/go"
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

var (
	numUnmarshallers = flag.Int("num-unmarshallers", 8, "number of goroutines used to unmarshal.")
	chSize           = flag.Int("ch-size", 8192, "size of channels used to communicate between goroutines.")
)

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "%s, git ref %s\n", os.Args[0], trace.CommitRef)
	flag.PrintDefaults()
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

// dscpChanged is the name of the one condition that needs decimal output, not hex.
const dscpChanged = "dscp.0.changed"

var condCache = make(map[string]*pto3.Condition)

func makeCondition(name string) *pto3.Condition {
	return &pto3.Condition{Name: name}
}

func makeDSCPCondition(old string) *pto3.Condition {
	name := "dscp." + old + ".changed"

	return &pto3.Condition{Name: name}
}

func makeChange(new string, toDec bool) string {
	num, err := strconv.ParseInt(new, 16, 64)
	if err != nil {
		num, err = strconv.ParseInt(new, 10, 64)
		if err != nil {
			return new
		}
	}
	if toDec {
		return fmt.Sprintf("%d", num)
	}
	return fmt.Sprintf("0x%x", num)
}

func appendObservation(o []pto3.Observation, start *time.Time, path *pto3.Path, cname string, new string) []pto3.Observation {
	return append(o, makeTbObs(start, path, makeCondition(cname), makeChange(new, false)))
}

func toDecString(val string) string {
	num, err := strconv.ParseInt(val, 16, 64)
	if err != nil {
		panic("can't convert string to decimal")
	}

	return fmt.Sprintf("%d", num)
}

func appendDSCPObservation(o []pto3.Observation, start *time.Time, path *pto3.Path, old, new string) []pto3.Observation {
	oldDec := toDecString(old)
	newDec := toDecString(new)

	return append(o, makeTbObs(start, path, makeDSCPCondition(oldDec), makeChange(newDec, true)))
}

func extractTraceboxV1Observations(srcIP string, tcpDestPort string, tbobs *tbObs) ([]pto3.Observation, error) {
	var ret = make([]pto3.Observation, 4)[0:0]
	start := time.Unix(tbobs.Timestamp, 0)

	var values = make(map[string]string)

	for i, h := range tbobs.Hops {
		var path *pto3.Path

		for _, m := range h.Modifications {
			if ptoCond, ok := tbToCond[m.Name]; ok {
				if stored, ok := values[m.Name]; !ok || m.Value != stored {
					path = makePathForChange(path, srcIP, tbobs, i)
					if ptoCond == dscpChanged {
						if !ok { // unknown DSCP value, we assume 0
							stored = "0"
						}
						ret = appendDSCPObservation(ret, &start, path, stored, m.Value)
					} else {
						ret = appendObservation(ret, &start, path, ptoCond, m.Value)
					}
					values[m.Name] = m.Value
				}
			}
		}
	}

	return ret, nil
}

// Reads lines from the srcCh, unmarshalls it and invokes the extraction function
// and sends the result to dstCh.
// If done (when srcCh is closed) will send true on doneCh.
func unmarshaller(srcCh chan []byte, dstCh chan []pto3.Observation,
	extractFunc func(string, string, *tbObs) ([]pto3.Observation, error),
	srcIP, tcpDestPort string, doneCh chan bool) {

	for {
		lineUntrimmed, ok := <-srcCh
		line := trace.TrimSpace(lineUntrimmed)

		if !ok {
			break
		}

		var tbobs tbObs

		if err := jsoniter.Unmarshal(line, &tbobs); err != nil {
			panic(err.Error())
		}

		obsen, err := extractFunc(srcIP, tcpDestPort, &tbobs)

		if err != nil {
			panic(err.Error())
		}

		dstCh <- obsen
	}

	doneCh <- true
}

func copyLine(line []byte) []byte {
	ret := make([]byte, len(line))
	copy(ret, line)

	return ret
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
	var extractFunc func(string, string, *tbObs) ([]pto3.Observation, error)

	switch md.Filetype(true) {
	case "tracebox-v1-ndjson":
		scanner = bufio.NewScanner(in)
		extractFunc = extractTraceboxV1Observations
	default:
		return fmt.Errorf("unsupported filetype %s", md.Filetype(true))
	}

	conditions := make(map[string]bool)

	srcCh := make(chan []byte, *chSize)
	dstCh := make(chan []pto3.Observation, *chSize)
	doneCh := make(chan bool)

	doneChans := make([]chan bool, *numUnmarshallers)

	for i := 0; i < *numUnmarshallers; i++ {
		doneChans[i] = make(chan bool)
		go unmarshaller(srcCh, dstCh, extractFunc, srcIP, tcpDestPort, doneChans[i])
	}

	// Spawn a goroutine to collect observations
	// and write them to out. 
	go func() {
		for {
			obsen, ok := <-dstCh

			if !ok {
				break
			}

			for _, o := range obsen {
				conditions[o.Condition.Name] = true
			}

			if err := pto3.WriteObservations(obsen, out); err != nil {
				panic(err.Error())
			}
		}

		doneCh <- true
	}()

	var lineno int

	// Split the input into lines and distribute the lines
	// among the unmarshallers.
	for scanner.Scan() {
		lineno++
		line := scanner.Bytes()

		if line[0] != '{' {
			continue
		}

		// This is NECESSARY because Scanner internally
		// reuses the buffer when calling `Scan`. This means
		// we need to copy the buffer.
		myLine := copyLine(line)

		srcCh <- myLine
	}

	// close the source channel to signal the unmarshallers
	// to start stopping.
	// The unmarshallers don't stop immediately of course as they might still be
	// performing computations or the source channel still has buffered elements.
	close(srcCh)

	// wait for all unmarshallers to have finished their job
	for i := 0; i < *numUnmarshallers; i++ {
		_ = <-doneChans[i]
	}

	// close the destination channel to send a stop signal to the
	// collector goroutine.
	close(dstCh)

	// wait for the collector goroutine to have actually stopped. 
	_ = <-doneCh

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
	mdout["_analyzer"] = "https://raw.githubusercontent.com/mami-project/pto3-trace/" +
		trace.CommitRef + "/cmd/pto3-trace/pto3-trace.json"

	bytes, err := jsoniter.Marshal(mdout)
	if err != nil {
		return fmt.Errorf("error marshaling metadata: %s", err.Error())
	}

	if _, err := fmt.Fprintf(out, "%s\n", bytes); err != nil {
		return fmt.Errorf("error writing metadata: %s", err.Error())
	}

	return nil
}

func normalizeV1(ec string, mdin *RawMetadata, mdout map[string]interface{}) ([]Observation, error) {

}

func f() int {

}

bla bla bla

func main() {
	flag.Usage = usage

	flag.Parse()

	mdfile := os.NewFile(3, ".piped_metadata.json")

	bytes, _, err := pto3.MapFile(os.Stdin)
	if err != nil {
		log.Fatalf("can't map stdin: %v", err)
	}

	sn := pto3.NewScanningNormalizer(metadataURL)
	sn.RegisterFiletype("tracebox-v1-ndjson", bufio.ScanLines, normalizeV1, nil)
	sn.RegisterFiletype("pathspider-v2-ndjson", bufio.ScanLines, normalizeV2, nil)

	// and run it
	log.Fatal(sn.Normalize(os.Stdin, mdfile, os.Stdout))

	if err := normalizeTrace(bytes, mdfile, os.Stdout); err != nil {
		log.Fatalf("error while normalising: %v", err)
	}

	if err := pto3.UnmapFile(bytes); err != nil {
		log.Fatalf("can't unmap stdin: %v", err)
	}
}
