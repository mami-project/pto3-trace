package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"regexp"
	"sort"
	"time"

	trace "github.com/mami-project/pto3-trace"
)

type tbStat struct {
	Count uint64 // how many instances were observed
}

type stats struct {
	Conditions     map[string]*tbStat
	FilesProcessed uint
	FilesTotal     uint
	TimeElapsed    time.Duration
	BytesProcessed uint64
}

func newStats() *stats {
	return &stats{
		Conditions: make(map[string]*tbStat),
	}
}

var (
	nWorkers = flag.Int("workers", 1, "number of workers in pool")
)

var conditions = newStats()

type job struct {
	Path string
}

var ipTCPRe = regexp.MustCompile(`(IP|TCP)::[^"]+`)

// findName finds a name enclosed in "" and containing a double
// double-colon. Examples: "IP::TTL", "IP::Checksum", "TCP::O::SACKPermitted".
func findNextName(b []byte) (int, []byte) {
	i := bytes.Index(b, []byte("::"))

	if i == -1 {
		return -1, nil
	}

	start := i
	for start >= 0 && b[start] != '"' {
		start--
	}

	if start < 0 {
		return -1, nil
	}

	end := i
	for end < len(b) && b[end] != '"' {
		end++
	}

	if end >= len(b) {
		return -1, nil
	}

	return end + 1, b[start+1 : end]
}

func processFile(path string, stats chan<- stats) {
	var stat = newStats()

	f, err := os.Open(path)
	if err != nil {
		log.Printf("ERROR: can't open \"%s\": %v", path, err)
		return
	}

	bytes, size, err := trace.MapFile(f)
	if err != nil {
		log.Printf("ERROR: can't map file \"%s\": %v", path, err)
		return
	}
	stat.BytesProcessed = uint64(size)

	region := bytes
	for end, match := findNextName(region); match != nil; end, match = findNextName(region) {
		matchs := string(match)
		if stat.Conditions[matchs] == nil {
			stat.Conditions[matchs] = new(tbStat)
		}
		stat.Conditions[matchs].Count++
		region = region[end:]
	}

	stats <- *stat

	if err := trace.UnmapFile(bytes); err != nil {
		log.Printf("ERROR: can't unmap \"%s\": %v", path, err)
	}
	if err := f.Close(); err != nil {
		log.Printf("ERROR: can't close \"%s\": %v", path, err)
	}
}

func worker(id int, jobs <-chan job, wstats chan<- stats, done chan<- bool) {
	for job := range jobs {
		processFile(job.Path, wstats)
	}
	done <- true
}

func processStats(n uint, wstats <-chan stats, quit <-chan bool, statc chan<- stats) {
	var conditions = newStats()
	conditions.FilesTotal = n

	for {
		select {
		case stat := <-wstats:
			for k, v := range stat.Conditions {
				if conditions.Conditions[k] == nil {
					conditions.Conditions[k] = new(tbStat)
				}
				conditions.Conditions[k].Count += v.Count
			}
			conditions.FilesProcessed++
			conditions.BytesProcessed += stat.BytesProcessed

		case statc <- *conditions:

		case <-quit:
			break
		}
	}
}

func fillJobs(paths []string, jobs chan<- job) {
	for _, p := range paths {
		jobs <- job{Path: p}
	}
	close(jobs)
}

func processFiles(paths []string) *stats {
	jobs := make(chan job, 2*(*nWorkers))
	done := make(chan bool, *nWorkers)
	workerStats := make(chan stats, 2*(*nWorkers))
	accumulatedStats := make(chan stats)
	squit := make(chan bool)

	go processStats(uint(len(paths)), workerStats, squit, accumulatedStats)

	go fillJobs(paths, jobs)

	for w := 1; w <= *nWorkers; w++ {
		go worker(w, jobs, workerStats, done)
	}

	const delay = 1
	ticker := time.Tick(delay * time.Second)
	workersDone := false
	var ret = newStats()
	var elapsed time.Duration

	for !workersDone {
		select {
		case <-ticker:
			elapsed += delay * time.Second
			*ret = <-accumulatedStats
			ret.TimeElapsed = elapsed
			workersDone = ret.FilesProcessed == ret.FilesTotal

			printProgress(ret)
		}
	}
	fmt.Println()

	for w := 1; w <= *nWorkers; w++ {
		<-done
	}

	return ret
}

func printProgress(s *stats) {
	frac := float64(s.FilesProcessed) / float64(s.FilesTotal)
	fmt.Printf("\r\x1b[2K%d/%d = %.2f%% done, elapsed = %s, ETA = %s, %s, %s",
		s.FilesProcessed, s.FilesTotal,
		100.0*frac, s.TimeElapsed,
		time.Duration(math.Round((1.0-frac)*float64(s.TimeElapsed)/frac)),
		sizeString(s.BytesProcessed), throughputString(s.BytesProcessed, s.TimeElapsed))
}

type sizeUnit struct {
	Name   string
	Factor float64
}

const unitFactor = 1024.0

var units = []sizeUnit{
	{Name: "B", Factor: 1.0},
	{Name: "Kib", Factor: unitFactor},
	{Name: "MiB", Factor: unitFactor * unitFactor},
	{Name: "GiB", Factor: unitFactor * unitFactor * unitFactor},
	{Name: "TiB", Factor: unitFactor * unitFactor * unitFactor * unitFactor},
}

func unit(size float64) sizeUnit {
	for _, unit := range units {
		throughput := size / unit.Factor
		if throughput < unitFactor {
			return unit
		}
	}

	return units[len(units)-1]
}

func throughputString(bytes uint64, elapsed time.Duration) string {
	throughput := float64(bytes) / float64(elapsed/time.Second)
	u := unit(throughput)

	return fmt.Sprintf("%.2f %s/s", throughput/u.Factor, u.Name)
}

func sizeString(bytes uint64) string {
	u := unit(float64(bytes))

	return fmt.Sprintf("%.2f %s", float64(bytes)/u.Factor, u.Name)
}

func keys(conditions map[string]*tbStat) []string {
	keys := make([]string, len(conditions))

	i := 0
	for k := range conditions {
		keys[i] = k
		i++
	}
	return keys
}

func printMap(conditions map[string]*tbStat) {
	ckeys := keys(conditions)

	sort.Slice(ckeys, func(i, j int) bool {
		return conditions[ckeys[i]].Count > conditions[ckeys[j]].Count
	})

	for _, k := range ckeys {
		fmt.Printf("%12d %s\n", conditions[k].Count, k)
	}
}

func main() {
	flag.Parse()
	s := processFiles(flag.Args())
	fmt.Println(s.FilesProcessed, "files in", s.TimeElapsed, "seconds")
	printMap(s.Conditions)
}
