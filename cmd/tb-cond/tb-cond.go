package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"sync"
	"syscall"
)

type tbStat struct {
	Count uint64 // how many instances were observed
}

var (
	nWorkers = flag.Int("workers", 1, "number of workers in pool")
)

var conditions = make(map[string]*tbStat)
var lock sync.Mutex

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

func processFile(path string) {
	fmt.Println(path, "started")

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
		lock.Lock()
		if conditions[matchs] == nil {
			conditions[matchs] = new(tbStat)
		}
		conditions[matchs].Count++
		lock.Unlock()
	}

	if err := unmapFile(bytes); err != nil {
		log.Printf("ERROR: can't unmap \"%s\": %v", path, err)
	}
	if err := f.Close(); err != nil {
		log.Printf("ERROR: can't close \"%s\": %v", path, err)
	}
	fmt.Println(path, "done")
}

func worker(id int, jobs <-chan job, done chan<- bool) {
	for job := range jobs {
		processFile(job.Path)
	}
	done <- true
}

func processFiles(paths []string) {
	jobs := make(chan job, 100)
	done := make(chan bool, *nWorkers)

	for w := 1; w <= *nWorkers; w++ {
		go worker(w, jobs, done)
	}

	for _, p := range paths {
		jobs <- job{Path: p}
	}
	close(jobs)

	for w := 1; w <= *nWorkers; w++ {
		<-done
	}
}

func keys() []string {
	keys := make([]string, len(conditions))

	i := 0
	for k := range conditions {
		keys[i] = k
		i++
	}
	return keys
}

func printMap() {
	ckeys := keys()

	sort.Slice(ckeys, func(i, j int) bool {
		return conditions[ckeys[i]].Count > conditions[ckeys[j]].Count
	})

	for _, k := range ckeys {
		fmt.Printf("%12d %s\n", conditions[k].Count, k)
	}
}

func main() {
	flag.Parse()
	processFiles(flag.Args())
	printMap()
}
