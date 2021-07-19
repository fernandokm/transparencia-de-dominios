package ds

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/schema"
)

type httpError struct {
	Base error
	Code int
}

func (he httpError) Error() string {
	return he.Base.Error()
}

type dtHandlerFunc func(url.Values) (interface{}, error)

func (handler dtHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data, err := handler(r.URL.Query())
	if err != nil {
		sendError(w, err)
	} else if err := sendJSON(w, data); err != nil {
		fmt.Printf("Error responding to %q: %v\n", r.URL, err)
	}
}

func sendError(w http.ResponseWriter, err error) {
	code := http.StatusNotFound
	if he, ok := err.(httpError); ok {
		code = he.Code
		err = he.Base
	}

	var errMsg string
	if me, ok := err.(schema.MultiError); ok {
		var sb strings.Builder
		for k, v := range me {
			fmt.Fprintf(&sb, "%s: %v\n", k, v)
		}
		errMsg = sb.String()
	} else {
		errMsg = err.Error()
	}
	http.Error(w, errMsg, code)
}

func sendJSON(w http.ResponseWriter, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		sendError(w, httpError{err, http.StatusInternalServerError})
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, err = w.Write(data)
	return err
}
