package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"regexp"
	"sort"
	"syscall"
	"time"
)

type tbStat struct {
	Count uint64 // how many instances were observed
}

type stats struct {
	Conditions     map[string]*tbStat
	FilesProcessed uint
	NFiles         uint
	TimeElapsed    float64 // in seconds
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

func mapFile(f *os.File) ([]byte, error) {
	// Adapted from https://github.com/golang/exp/blob/master/mmap/mmap_unix.go
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	size := fi.Size()
	if size < 0 {
		return nil, fmt.Errorf("mmap: file %q has negative size", f.Name())
	}
	if size != int64(int(size)) {
		return nil, fmt.Errorf("mmap: file %q is too large", f.Name())
	}

	data, err := syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func unmapFile(bytes []byte) error {
	return syscall.Munmap(bytes)
}

func processFile(path string, stats chan<- stats) {
	var stat = newStats()

	f, err := os.Open(path)
	if err != nil {
		log.Printf("ERROR: can't open \"%s\": %v", path, err)
		return
	}

	bytes, err := mapFile(f)
	if err != nil {
		log.Printf("ERROR: can't map file \"%s\": %v", path, err)
		return
	}

	matches := ipTCPRe.FindAll(bytes, -1)
	for _, match := range matches {
		matchs := string(match)
		if stat.Conditions[matchs] == nil {
			stat.Conditions[matchs] = new(tbStat)
		}
		stat.Conditions[matchs].Count++
	}

	stats <- *stat

	if err := unmapFile(bytes); err != nil {
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
	conditions.NFiles = n

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
	var nSec uint

	for !workersDone {
		select {
		case <-ticker:
			nSec += delay
			*ret = <-accumulatedStats
			workersDone = ret.FilesProcessed == ret.NFiles
			frac := float64(ret.FilesProcessed) / float64(ret.NFiles)
			fmt.Printf("\r%d/%d = %.2f%% done, elapsed = %d sec, ETA = %g sec",
				ret.FilesProcessed, ret.NFiles,
				100.0*frac, nSec, math.Round((1.0-frac)*float64(nSec)/frac))
		}
	}
	fmt.Println()

	for w := 1; w <= *nWorkers; w++ {
		<-done
	}

	ret.TimeElapsed = float64(nSec)

	return ret
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
