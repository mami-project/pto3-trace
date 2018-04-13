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
)

type tbStat struct {
	Count uint64 // how many instances were observed
}

var conditions = make(map[string]*tbStat)

//sed -n -e 's/^.*IP::\([^"]*\).*$/\1/p' -e 's/^.*TCP::\([^"]*\).*$/\1/p'

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
				if conditions[key] == nil {
					conditions[key] = new(tbStat)
				}
				conditions[key].Count++
			}
		}
	}
	if err := f.Close(); err != nil {
		log.Printf("ERROR: can't close \"%s\": %v", path, err)
	}
}

func processFiles(paths []string) {
	for _, p := range paths {
		fmt.Print(p, "...")
		processFile(p)
		fmt.Println()
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
