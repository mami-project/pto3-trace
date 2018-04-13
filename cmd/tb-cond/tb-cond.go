package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
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

var (
	ipRe  = regexp.MustCompile(`(IP::[^"]*)`)
	tcpRe = regexp.MustCompile(`(TCP::[^"]*)`)
)

func processFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("ERROR: can't open \"%s\": %v", path, err)
		return
	}

	var res = []*regexp.Regexp{ipRe, tcpRe}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		for _, re := range res {
			matches := re.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				key := match[1]

				lock.Lock()
				if conditions[key] == nil {
					conditions[key] = new(tbStat)
				}
				conditions[key].Count++
				lock.Unlock()
			}
		}
	}
	if err := f.Close(); err != nil {
		log.Printf("ERROR: can't close \"%s\": %v", path, err)
	}
	fmt.Println(path)
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
