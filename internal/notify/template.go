package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"reflect"
	"strings"
	"sync"
	"text/template"
	"time"
	"unicode/utf8"
)

// TemplateData is the value a destination template is executed with.
type TemplateData struct {
	Event    EventMeta
	Scan     ScanInfo
	Findings []FindingInfo
	// Count is len(Findings) after per-destination namespace filtering.
	Count int
	// Secrets is the destination's ${ENV}-expanded secrets map.
	Secrets map[string]string
	BaseURL string
}

// EventMeta is .Event in templates.
type EventMeta struct {
	Type    string
	Time    time.Time
	Cluster string
}

// Default render limits.
const (
	DefaultMaxBodyBytes   = 256 << 10
	DefaultRenderTimeout  = 2 * time.Second
	defaultTruncateSuffix = "…"
)

var errBodyTooLarge = errors.New("rendered body exceeds size limit")

// funcMap returns the safe template function set. now is the engine clock.
// It deliberately contains no env, file, network or exec access.
func funcMap(now func() time.Time) template.FuncMap {
	return template.FuncMap{
		"json":            tplJSON,
		"jsonEscape":      tplJSONEscape,
		"quote":           tplQuote,
		"join":            tplJoin,
		"upper":           func(v any) string { return strings.ToUpper(toString(v)) },
		"lower":           func(v any) string { return strings.ToLower(toString(v)) },
		"truncate":        tplTruncate,
		"default":         tplDefault,
		"len":             tplLen,
		"now":             func() time.Time { return now().UTC() },
		"formatTime":      tplFormatTime,
		"countBySeverity": tplCountBySeverity,
		"first":           tplFirst,
		"add":             func(a, b int) int { return a + b },
		"sub":             func(a, b int) int { return a - b },
		// Shadow the reflection-based builtin; templates never get funcs.
		"call": func(...any) (any, error) { return nil, errors.New("call is disabled") },
	}
}

func tplJSON(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(true) // </script> -> </script>
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// tplJSONEscape returns the JSON-escaped content of s without the surrounding
// quotes, for use inside a string literal written in the template.
func tplJSONEscape(v any) (string, error) {
	s, err := tplJSON(toString(v))
	if err != nil {
		return "", err
	}
	return s[1 : len(s)-1], nil
}

// tplQuote renders any value as a JSON string literal.
func tplQuote(v any) (string, error) { return tplJSON(toString(v)) }

func toString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case fmt.Stringer:
		return x.String()
	case error:
		return x.Error()
	}
	return fmt.Sprint(v)
}

func tplJoin(sep string, list any) (string, error) {
	rv := reflect.ValueOf(list)
	if !rv.IsValid() {
		return "", nil
	}
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return "", fmt.Errorf("join: expected a list, got %T", list)
	}
	parts := make([]string, rv.Len())
	for i := range parts {
		parts[i] = toString(rv.Index(i).Interface())
	}
	return strings.Join(parts, sep), nil
}

func tplTruncate(n int, v any) (string, error) {
	if n < 0 {
		return "", errors.New("truncate: negative length")
	}
	s := toString(v)
	if utf8.RuneCountInString(s) <= n {
		return s, nil
	}
	if n == 0 {
		return "", nil
	}
	r := []rune(s)
	return string(r[:n-1]) + defaultTruncateSuffix, nil
}

func tplDefault(def, v any) any {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() || rv.IsZero() {
		return def
	}
	switch rv.Kind() {
	case reflect.Slice, reflect.Map, reflect.String, reflect.Array:
		if rv.Len() == 0 {
			return def
		}
	}
	return v
}

func tplLen(v any) (int, error) {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return 0, nil
	}
	switch rv.Kind() {
	case reflect.Slice, reflect.Map, reflect.String, reflect.Array, reflect.Chan:
		return rv.Len(), nil
	}
	return 0, fmt.Errorf("len of %T", v)
}

func tplFormatTime(layout string, t any) (string, error) {
	switch x := t.(type) {
	case time.Time:
		return x.UTC().Format(layout), nil
	case *time.Time:
		if x == nil {
			return "", nil
		}
		return x.UTC().Format(layout), nil
	}
	return "", fmt.Errorf("formatTime: expected time, got %T", t)
}

// tplCountBySeverity returns a map severity->count, or the count for one
// severity when given (case-insensitive).
func tplCountBySeverity(findings []FindingInfo, severity ...string) (any, error) {
	if len(severity) > 1 {
		return nil, errors.New("countBySeverity: at most one severity")
	}
	m := map[string]int{}
	for _, f := range findings {
		m[strings.ToUpper(f.Severity)]++
	}
	if len(severity) == 1 {
		return m[strings.ToUpper(severity[0])], nil
	}
	return m, nil
}

func tplFirst(n int, list any) (any, error) {
	if n < 0 {
		return nil, errors.New("first: negative count")
	}
	rv := reflect.ValueOf(list)
	if !rv.IsValid() {
		return list, nil
	}
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return nil, fmt.Errorf("first: expected a list, got %T", list)
	}
	if rv.Len() <= n {
		return list, nil
	}
	return rv.Slice(0, n).Interface(), nil
}

// parseTemplate parses a destination body template with strict options.
func parseTemplate(name, text string, funcs template.FuncMap) (*template.Template, error) {
	return template.New(name).Option("missingkey=error").Funcs(funcs).Parse(text)
}

// limitedBuffer caps output and can be aborted so a runaway template stops at
// its next write.
type limitedBuffer struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	max     int
	aborted bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.aborted {
		return 0, errors.New("render aborted")
	}
	if b.buf.Len()+len(p) > b.max {
		return 0, errBodyTooLarge
	}
	return b.buf.Write(p)
}

func (b *limitedBuffer) abort() {
	b.mu.Lock()
	b.aborted = true
	b.mu.Unlock()
}

// execute runs t with a size cap and a wall-clock timeout.
func execute(t *template.Template, data any, maxBytes int, timeout time.Duration) ([]byte, error) {
	w := &limitedBuffer{max: maxBytes}
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("template panic: %v", r)
			}
		}()
		done <- t.Execute(w, data)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			if errors.Is(err, errBodyTooLarge) {
				return nil, fmt.Errorf("%w (%d bytes)", errBodyTooLarge, maxBytes)
			}
			return nil, err
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		return bytes.Clone(w.buf.Bytes()), nil
	case <-timer.C:
		w.abort()
		return nil, fmt.Errorf("template execution exceeded %s", timeout)
	}
}

// isJSONContentType reports whether ct is application/json or a +json type.
func isJSONContentType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(ct))
	}
	return mt == "application/json" || strings.HasSuffix(mt, "+json")
}
