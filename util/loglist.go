package util

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"

	"github.com/google/certificate-transparency-go/loglist2"
)

var (
	//go:embed loglist.json
	logListRaw   string
	logListOnce  sync.Once
	logListValue *loglist2.LogList
)

// GetLogList returns a fixed log list that is loaded from an embeded file.
// The returned loglist is the same throughout the runtime of the program
// and should therefore not be modified.
func GetLogList() *loglist2.LogList {
	logListOnce.Do(func() {
		list, err := loglist2.NewFromJSON([]byte(logListRaw))
		if err != nil {
			panic(fmt.Errorf("error parsing loglist: %w", err))
		}
		logListValue = list
	})

	return logListValue
}

// FindLogs is similar to loglist2.LogList.FuzzyFindLog,
// but also tries to use search by strings.lower(input) in the case of URLs.
func FindLogs(input string) []*loglist2.Log {
	list := GetLogList()

	// First, try to use loglist2's fuzzy matching.
	// If there are any matches, then either:
	// - it's a URL, in which case the (unique) match is the same url that
	//   would be matched in the next step; or
	// - it's a name or hash, in which case no url would be matched in the
	//   next step,
	// so we can return immediately and skip the next step.
	if fuzzyLogs := list.FuzzyFindLog(input); len(fuzzyLogs) > 0 {
		return fuzzyLogs
	}

	// Manually lookup by lower(url) because loglist2's URL matching
	// is case sensitive and most (all?) logs appear to be listed with lower case URLs.
	if log := list.FindLogByURL(strings.ToLower(input)); log != nil {
		return []*loglist2.Log{log}
	}
	return nil
}
