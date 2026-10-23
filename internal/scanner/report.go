package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// trivyReport is the subset of Trivy's JSON report (SchemaVersion 2) we use.
type trivyReport struct {
	SchemaVersion int    `json:"SchemaVersion"`
	ArtifactName  string `json:"ArtifactName"`
	Metadata      struct {
		OS *struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
		} `json:"OS"`
		RepoDigests []string `json:"RepoDigests"`
	} `json:"Metadata"`
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			PkgPath          string `json:"PkgPath"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			PrimaryURL       string `json:"PrimaryURL"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// ParseReport locates Trivy's JSON report in r (which may contain log noise
// before or after it), validates it and returns the vulnerabilities matching
// severities (all when empty), deduplicated. Errors are *Error of KindOutput.
func ParseReport(r io.Reader, severities []string) (*Result, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, outputErr("read scanner output", err, "")
	}
	rep, err := findReport(data)
	if err != nil {
		return nil, err
	}

	allowed := map[string]bool{}
	for _, s := range severities {
		allowed[strings.ToUpper(strings.TrimSpace(s))] = true
	}
	type dk struct{ id, pkg, path, ver string }
	seen := map[dk]bool{}
	res := &Result{ImageRef: rep.ArtifactName, Vulnerabilities: []Vulnerability{}}
	if rep.Metadata.OS != nil {
		res.OS = strings.TrimSpace(rep.Metadata.OS.Family + " " + rep.Metadata.OS.Name)
	}
	for _, d := range rep.Metadata.RepoDigests {
		if _, digest, ok := strings.Cut(d, "@"); ok && digest != "" {
			res.ImageDigest = digest
			break
		}
	}
	if res.ImageDigest == "" {
		if _, digest, ok := strings.Cut(rep.ArtifactName, "@"); ok {
			res.ImageDigest = digest
		}
	}
	for _, rr := range rep.Results {
		for _, v := range rr.Vulnerabilities {
			sev := strings.ToUpper(v.Severity)
			if len(allowed) > 0 && !allowed[sev] {
				continue
			}
			if v.VulnerabilityID == "" {
				continue
			}
			k := dk{v.VulnerabilityID, v.PkgName, v.PkgPath, v.InstalledVersion}
			if seen[k] {
				continue
			}
			seen[k] = true
			res.Vulnerabilities = append(res.Vulnerabilities, Vulnerability{
				VulnerabilityID:  v.VulnerabilityID,
				PkgName:          v.PkgName,
				PkgPath:          v.PkgPath,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				Severity:         sev,
				Title:            v.Title,
				PrimaryURL:       v.PrimaryURL,
				Target:           rr.Target,
			})
		}
	}
	return res, nil
}

// findReport tries every line starting with '{' until one decodes into an
// object that looks like a Trivy report (has ArtifactName or Results).
func findReport(data []byte) (*trivyReport, error) {
	var firstErr error
	candidates := 0
	for off := 0; off < len(data); {
		lineEnd := bytes.IndexByte(data[off:], '\n')
		line := data[off:]
		next := len(data)
		if lineEnd >= 0 {
			line = data[off : off+lineEnd]
			next = off + lineEnd + 1
		}
		trimmed := bytes.TrimLeft(line, " \t\r")
		if len(trimmed) > 0 && trimmed[0] == '{' {
			candidates++
			start := off + (len(line) - len(trimmed))
			rep, err := decodeAt(data[start:])
			if err == nil {
				return rep, nil
			}
			if firstErr == nil {
				firstErr = err
			}
		}
		off = next
	}
	if candidates == 0 {
		return nil, outputErr("no JSON report found in scanner output", nil, tail(data, 512))
	}
	return nil, outputErr("invalid Trivy JSON report", firstErr, tail(data, 512))
}

func decodeAt(b []byte) (*trivyReport, error) {
	var raw json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&raw); err != nil {
		return nil, err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, err
	}
	_, hasName := keys["ArtifactName"]
	_, hasResults := keys["Results"]
	if !hasName && !hasResults {
		return nil, fmt.Errorf("JSON object is not a Trivy report (no ArtifactName or Results)")
	}
	var rep trivyReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, err
	}
	return &rep, nil
}

func outputErr(msg string, err error, diag string) *Error {
	return &Error{Kind: KindOutput, Retryable: true, Msg: msg, Err: err, Diagnostics: diag}
}

// tail returns at most n trailing bytes of b as a string.
func tail(b []byte, n int) string {
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return strings.ToValidUTF8(string(b), "")
}
