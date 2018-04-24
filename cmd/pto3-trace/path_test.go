package main

import (
	"encoding/json"
	"log"
	"testing"
)

const src = "128.112.139.42"
const noPath = `{"dst":"88.212.202.2", "r":"tcp-rst", "s":1462315337, "h":[]}`
const onePath = `{"dst":"88.212.202.2", "r":"tcp-rst", "s":1462315337, "h":[{"ha":"128.112.139.1", "t":1, "i":2, "m":[], "a":[], "d":[]}]}`
const twoPath = `{"dst":"88.212.202.2", "r":"tcp-rst", "s":1462315337, "h":[{"ha":"128.112.139.1", "t":1, "i":2, "m":[], "a":[], "d":[]}, {"ha":"128.112.12.57", "t":2, "i":2, "m":[], "a":[], "d":[]}]}`
const longPath = `{"dst":"88.212.202.2", "r":"tcp-rst", "s":1462315337, "h":[{"ha":"128.112.139.1", "t":1, "i":2, "m":[], "a":[], "d":[]},{"ha":"128.112.12.57", "t":2, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"128.112.12.142", "t":3, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"63.138.53.73", "t":4, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"67.151.33.22", "t":5, "i":3, "m":[{"n":"IP::TTL", "v":"02"}, {"n":"IP::Checksum", "v":"8a56"}], "a":[], "d":[]},{"ha":"63.138.198.162", "t":6, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"213.248.95.21", "t":7, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"62.115.112.248", "t":8, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"62.115.141.96", "t":9, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"62.115.139.166", "t":10, "i":3, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"62.115.116.233", "t":11, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"62.115.144.69", "t":12, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"88.212.194.82", "t":13, "i":3, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"88.212.202.2", "t":14, "i":0, "m":[], "a":[], "d":[]}]}`
const onePathStar = `{"dst":"88.212.202.2", "r":"tcp-rst", "s":1462315337, "h":[{"ha":"*", "t":1, "i":2, "m":[], "a":[], "d":[]}]}`
const twoPathStarBeginning = `{"dst":"88.212.202.2", "r":"tcp-rst", "s":1462315337, "h":[{"ha":"*", "t":1, "i":2, "m":[], "a":[], "d":[]}, {"ha":"128.112.12.57", "t":2, "i":2, "m":[], "a":[], "d":[]}]}`
const twoPathStarEnd = `{"dst":"88.212.202.2", "r":"tcp-rst", "s":1462315337, "h":[{"ha":"128.112.139.1", "t":1, "i":2, "m":[], "a":[], "d":[]}, {"ha":"*", "t":2, "i":2, "m":[], "a":[], "d":[]}]}`
const longPathStarBeginning = `{"dst":"88.212.202.2", "r":"tcp-rst", "s":1462315337, "h":[{"ha":"*", "t":1, "i":2, "m":[], "a":[], "d":[]},{"ha":"128.112.12.57", "t":2, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"128.112.12.142", "t":3, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"63.138.53.73", "t":4, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"67.151.33.22", "t":5, "i":3, "m":[{"n":"IP::TTL", "v":"02"}, {"n":"IP::Checksum", "v":"8a56"}], "a":[], "d":[]},{"ha":"63.138.198.162", "t":6, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"213.248.95.21", "t":7, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"62.115.112.248", "t":8, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"62.115.141.96", "t":9, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"62.115.139.166", "t":10, "i":3, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"62.115.116.233", "t":11, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"62.115.144.69", "t":12, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"88.212.194.82", "t":13, "i":3, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"88.212.202.2", "t":14, "i":0, "m":[], "a":[], "d":[]}]}`
const longPathStarMiddle = `{"dst":"88.212.202.2", "r":"tcp-rst", "s":1462315337, "h":[{"ha":"128.112.139.1", "t":1, "i":2, "m":[], "a":[], "d":[]},{"ha":"128.112.12.57", "t":2, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"128.112.12.142", "t":3, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"63.138.53.73", "t":4, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"67.151.33.22", "t":5, "i":3, "m":[{"n":"IP::TTL", "v":"02"}, {"n":"IP::Checksum", "v":"8a56"}], "a":[], "d":[]},{"ha":"63.138.198.162", "t":6, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"213.248.95.21", "t":7, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"62.115.112.248", "t":8, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"62.115.141.96", "t":9, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"62.115.139.166", "t":10, "i":3, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"62.115.116.233", "t":11, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"*", "t":12, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"88.212.194.82", "t":13, "i":3, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"88.212.202.2", "t":14, "i":0, "m":[], "a":[], "d":[]}]}`
const longPathStarEnd = `{"dst":"88.212.202.2", "r":"tcp-rst", "s":1462315337, "h":[{"ha":"128.112.139.1", "t":1, "i":2, "m":[], "a":[], "d":[]},{"ha":"128.112.12.57", "t":2, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"128.112.12.142", "t":3, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"63.138.53.73", "t":4, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"67.151.33.22", "t":5, "i":3, "m":[{"n":"IP::TTL", "v":"02"}, {"n":"IP::Checksum", "v":"8a56"}], "a":[], "d":[]},{"ha":"63.138.198.162", "t":6, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"213.248.95.21", "t":7, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"62.115.112.248", "t":8, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"62.115.141.96", "t":9, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"62.115.139.166", "t":10, "i":3, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"62.115.116.233", "t":11, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"62.115.144.69", "t":12, "i":2, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"88.212.194.82", "t":13, "i":3, "m":[{"n":"IP::TTL", "v":"01"}, {"n":"IP::Checksum", "v":"8b56"}], "a":[], "d":[]},{"ha":"*", "t":14, "i":0, "m":[], "a":[], "d":[]}]}`

func tbObsFromString(s string) *tbObs {
	var ret tbObs
	if err := json.Unmarshal([]byte(s), &ret); err != nil {
		log.Panicf("can't unmarshal test data %v: %v", s, err)
	}
	return &ret
}

func testPathsEquals(t *testing.T, want, got string) {
	if want != got {
		t.Errorf("paths not equal: want \"%s\", got \"%s\"", want, got)
	}
}

func TestNoPathChange(t *testing.T) {
	tbobs := tbObsFromString(noPath)
	path := makePathForChange(nil, src, tbobs, 0)
	testPathsEquals(t, "128.112.139.42 88.212.202.2", path.String)
}

func TestOnePathChange(t *testing.T) {
	tbobs := tbObsFromString(onePath)
	path := makePathForChange(nil, src, tbobs, 0)
	testPathsEquals(t, "128.112.139.42 128.112.139.1 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 1)
	testPathsEquals(t, "128.112.139.42 128.112.139.1 88.212.202.2", path.String)
}

func TestOnePathStarChange(t *testing.T) {
	tbobs := tbObsFromString(onePathStar)
	path := makePathForChange(nil, src, tbobs, 0)
	testPathsEquals(t, "128.112.139.42 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 1)
	testPathsEquals(t, "128.112.139.42 * 88.212.202.2", path.String)
}

func TestTwoPathChange(t *testing.T) {
	tbobs := tbObsFromString(twoPath)
	path := makePathForChange(nil, src, tbobs, 0)
	testPathsEquals(t, "128.112.139.42 128.112.139.1 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 1)
	testPathsEquals(t, "128.112.139.42 128.112.139.1 128.112.12.57 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 2)
	testPathsEquals(t, "128.112.139.42 * 128.112.12.57 88.212.202.2", path.String)
}

func TestLongPathChange(t *testing.T) {
	tbobs := tbObsFromString(longPath)
	path := makePathForChange(nil, src, tbobs, 0)
	testPathsEquals(t, "128.112.139.42 128.112.139.1 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 1)
	testPathsEquals(t, "128.112.139.42 128.112.139.1 128.112.12.57 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 2)
	testPathsEquals(t, "128.112.139.42 * 128.112.12.57 128.112.12.142 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 3)
	testPathsEquals(t, "128.112.139.42 * 128.112.12.142 63.138.53.73 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 4)
	testPathsEquals(t, "128.112.139.42 * 63.138.53.73 67.151.33.22 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 5)
	testPathsEquals(t, "128.112.139.42 * 67.151.33.22 63.138.198.162 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 6)
	testPathsEquals(t, "128.112.139.42 * 63.138.198.162 213.248.95.21 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 7)
	testPathsEquals(t, "128.112.139.42 * 213.248.95.21 62.115.112.248 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 8)
	testPathsEquals(t, "128.112.139.42 * 62.115.112.248 62.115.141.96 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 9)
	testPathsEquals(t, "128.112.139.42 * 62.115.141.96 62.115.139.166 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 10)
	testPathsEquals(t, "128.112.139.42 * 62.115.139.166 62.115.116.233 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 11)
	testPathsEquals(t, "128.112.139.42 * 62.115.116.233 62.115.144.69 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 12)
	testPathsEquals(t, "128.112.139.42 * 62.115.144.69 88.212.194.82 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 13)
	testPathsEquals(t, "128.112.139.42 * 88.212.194.82 88.212.202.2", path.String)
}

func TestLongPathStarBeginningChange(t *testing.T) {
	tbobs := tbObsFromString(longPathStarBeginning)

	// This must give the wrong result since we can't have * give anything
	// in the a[], m[] or d[] arrays.
	//
	//path := makePathForChange(nil, src, tbobs, 0)
	//testPathsEquals(t, "128.112.139.42 * 88.212.202.2", path.String)
	path := makePathForChange(nil, src, tbobs, 1)
	testPathsEquals(t, "128.112.139.42 * 128.112.12.57 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 2)
	testPathsEquals(t, "128.112.139.42 * 128.112.12.57 128.112.12.142 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 3)
	testPathsEquals(t, "128.112.139.42 * 128.112.12.142 63.138.53.73 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 4)
	testPathsEquals(t, "128.112.139.42 * 63.138.53.73 67.151.33.22 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 5)
	testPathsEquals(t, "128.112.139.42 * 67.151.33.22 63.138.198.162 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 6)
	testPathsEquals(t, "128.112.139.42 * 63.138.198.162 213.248.95.21 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 7)
	testPathsEquals(t, "128.112.139.42 * 213.248.95.21 62.115.112.248 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 8)
	testPathsEquals(t, "128.112.139.42 * 62.115.112.248 62.115.141.96 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 9)
	testPathsEquals(t, "128.112.139.42 * 62.115.141.96 62.115.139.166 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 10)
	testPathsEquals(t, "128.112.139.42 * 62.115.139.166 62.115.116.233 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 11)
	testPathsEquals(t, "128.112.139.42 * 62.115.116.233 62.115.144.69 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 12)
	testPathsEquals(t, "128.112.139.42 * 62.115.144.69 88.212.194.82 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 13)
	testPathsEquals(t, "128.112.139.42 * 88.212.194.82 88.212.202.2", path.String)
}

func TestLongPathStarMiddleChange(t *testing.T) {
	tbobs := tbObsFromString(longPathStarMiddle)

	path := makePathForChange(nil, src, tbobs, 0)
	testPathsEquals(t, "128.112.139.42 128.112.139.1 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 1)
	testPathsEquals(t, "128.112.139.42 128.112.139.1 128.112.12.57 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 2)
	testPathsEquals(t, "128.112.139.42 * 128.112.12.57 128.112.12.142 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 3)
	testPathsEquals(t, "128.112.139.42 * 128.112.12.142 63.138.53.73 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 4)
	testPathsEquals(t, "128.112.139.42 * 63.138.53.73 67.151.33.22 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 5)
	testPathsEquals(t, "128.112.139.42 * 67.151.33.22 63.138.198.162 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 6)
	testPathsEquals(t, "128.112.139.42 * 63.138.198.162 213.248.95.21 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 7)
	testPathsEquals(t, "128.112.139.42 * 213.248.95.21 62.115.112.248 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 8)
	testPathsEquals(t, "128.112.139.42 * 62.115.112.248 62.115.141.96 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 9)
	testPathsEquals(t, "128.112.139.42 * 62.115.141.96 62.115.139.166 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 10)
	testPathsEquals(t, "128.112.139.42 * 62.115.139.166 62.115.116.233 * 88.212.202.2", path.String)
	//path = makePathForChange(nil, src, tbobs, 11)
	//testPathsEquals(t, "128.112.139.42 * 62.115.116.233 62.115.144.69 * 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 12)
	testPathsEquals(t, "128.112.139.42 * 88.212.194.82 88.212.202.2", path.String)
	path = makePathForChange(nil, src, tbobs, 13)
	testPathsEquals(t, "128.112.139.42 * 88.212.194.82 88.212.202.2", path.String)
}
