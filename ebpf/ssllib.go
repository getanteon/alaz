package ebpf

import (
	"fmt"
	"regexp"
	"strings"
)

var libSSLRegex string = `.*libssl(?P<AdjacentVersion>\d)*-*.*\.so\.*(?P<SuffixVersion>[0-9\.]+)*.*`
var re *regexp.Regexp

func init() {
	re = regexp.MustCompile(libSSLRegex)
}

type sslLib struct {
	path    string
	version string
}

func parseSSLlib(text string) (map[string]*sslLib, error) {
	res := make(map[string]*sslLib)
	matches := re.FindAllStringSubmatch(text, -1)

	if matches == nil {
		return nil, fmt.Errorf("no ssl lib found")
	}

	for _, groups := range matches {
		match := groups[0]

		paramsMap := make(map[string]string)
		for i, name := range re.SubexpNames() {
			if i > 0 && i <= len(groups) {
				paramsMap[name] = groups[i]
			}
		}

		// paramsMap
		// k : AdjacentVersion or SuffixVersion
		// v : 1.0.2 or 3 ...

		var version string
		if paramsMap["AdjacentVersion"] != "" {
			version = paramsMap["AdjacentVersion"]
		} else if paramsMap["SuffixVersion"] != "" {
			version = paramsMap["SuffixVersion"]
		} else {
			continue
		}

		// add "v." prefix
		if version != "" {
			version = "v" + version
		}

		path := getPath(match)
		res[path] = &sslLib{
			path:    path,
			version: version,
		}
	}

	return res, nil
}

func getPath(mappingLine string) string {
	mappingLine = strings.TrimSpace(mappingLine)
	elems := strings.Split(mappingLine, " ")

	// edge case
	// /usr/lib64/libssl.so.1.0.2k (deleted)

	path := elems[len(elems)-1]

	if strings.Contains(path, "(deleted)") {
		path = elems[len(elems)-2]
	}

	return path
}
