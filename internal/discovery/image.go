package discovery

import "strings"

const (
	dockerHubDomain = "docker.io"
	defaultTag      = "latest"
)

// imageName is a parsed, normalized container image reference.
type imageName struct {
	// Repository is fully qualified, e.g. docker.io/library/nginx.
	Repository string
	Tag        string
	Digest     string
}

// String returns repo@digest when a digest is known, else repo:tag.
func (n imageName) String() string {
	if n.Digest != "" {
		return n.Repository + "@" + n.Digest
	}
	return n.TagRef()
}

// TagRef returns repo:tag (tag defaults to latest).
func (n imageName) TagRef() string {
	tag := n.Tag
	if tag == "" {
		tag = defaultTag
	}
	return n.Repository + ":" + tag
}

// parseImage normalizes an image reference such as "nginx",
// "nginx:1.27", "ghcr.io/org/app@sha256:..", "localhost:5000/app:v1".
func parseImage(ref string) imageName {
	ref = strings.TrimSpace(ref)
	var n imageName
	if i := strings.Index(ref, "@"); i >= 0 {
		n.Digest = ref[i+1:]
		ref = ref[:i]
	}
	// A tag is a ':' after the last '/'.
	lastSlash := strings.LastIndex(ref, "/")
	if i := strings.LastIndex(ref, ":"); i > lastSlash {
		n.Tag = ref[i+1:]
		ref = ref[:i]
	}
	n.Repository = normalizeRepository(ref)
	if n.Tag == "" && n.Digest == "" {
		n.Tag = defaultTag
	}
	return n
}

// normalizeRepository qualifies Docker Hub short names and lowercases the
// registry host.
func normalizeRepository(repo string) string {
	if repo == "" {
		return repo
	}
	domain, rest := "", repo
	if i := strings.Index(repo, "/"); i >= 0 {
		first := repo[:i]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			domain, rest = strings.ToLower(first), repo[i+1:]
		}
	}
	switch domain {
	case "", "index.docker.io", "registry-1.docker.io":
		domain = dockerHubDomain
	}
	if domain == dockerHubDomain && !strings.Contains(rest, "/") {
		rest = "library/" + rest
	}
	return domain + "/" + rest
}

// imageIDPrefixes are runtime-specific schemes on containerStatuses[].imageID.
var imageIDPrefixes = []string{"docker-pullable://", "docker://", "containerd://", "cri-o://"}

// parseImageID extracts the repository (may be empty) and digest from a
// containerStatuses[].imageID. ok is false when no usable digest is present.
func parseImageID(id string) (repo, digest string, ok bool) {
	id = strings.TrimSpace(id)
	for _, p := range imageIDPrefixes {
		id = strings.TrimPrefix(id, p)
	}
	if id == "" {
		return "", "", false
	}
	if i := strings.Index(id, "@"); i >= 0 {
		d := id[i+1:]
		if !validDigest(d) {
			return "", "", false
		}
		return normalizeRepository(stripTag(id[:i])), d, true
	}
	if validDigest(id) {
		return "", id, true
	}
	return "", "", false
}

func stripTag(repo string) string {
	lastSlash := strings.LastIndex(repo, "/")
	if i := strings.LastIndex(repo, ":"); i > lastSlash {
		return repo[:i]
	}
	return repo
}

func validDigest(d string) bool {
	alg, hex, found := strings.Cut(d, ":")
	if !found || alg == "" || len(hex) < 32 {
		return false
	}
	for _, c := range hex {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
