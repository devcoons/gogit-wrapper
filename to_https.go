package gitwrap

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// SshToHttps converts a Git remote (SSH/HTTP/HTTPS/GIT/SCP-like) to canonical HTTPS.
// It is host-agnostic and includes Azure DevOps mappings.
//
// Examples:
//
//	git@bitbucket.org:org/repo.git         -> https://bitbucket.org/org/repo.git
//	ssh://git@bitbucket.org/org/repo.git   -> https://bitbucket.org/org/repo.git
//	https://bitbucket.org/org/repo.git     -> https://bitbucket.org/org/repo.git (normalized)
//	git://bitbucket.org/org/repo.git       -> https://bitbucket.org/org/repo.git
//
// Policy:
//   - Always output https://
//   - Drop embedded credentials, query, and fragment
//   - Normalize path (single leading slash, forward slashes)
//   - Strip default ports (22, 443); drop non-standard ports unless keepNonStandardPort=true
//   - Reject local paths and file:// remotes
func SshToHttps(remote string, keepNonStandardPort bool) (string, error) {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return "", errors.New("empty remote")
	}

	low := strings.ToLower(remote)

	// Already HTTP(S)
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
		u, err := url.Parse(remote)
		if err != nil {
			return "", fmt.Errorf("parse https/http: %w", err)
		}
		u.Scheme = "https"
		u.User = nil
		u.RawQuery, u.Fragment = "", ""
		u.Path = cleanPath(u.Path)
		u.Host = normalizeHostPort(u.Host, keepNonStandardPort)
		return hostSpecificPostprocess(u), nil
	}

	// git:// -> https://
	if strings.HasPrefix(low, "git://") {
		u, err := url.Parse(remote)
		if err != nil {
			return "", fmt.Errorf("parse git://: %w", err)
		}
		u.Scheme = "https"
		u.User = nil
		u.RawQuery, u.Fragment = "", ""
		u.Path = cleanPath(u.Path)
		u.Host = normalizeHostPort(u.Host, keepNonStandardPort)
		return hostSpecificPostprocess(u), nil
	}

	// ssh:// -> https://
	if strings.HasPrefix(low, "ssh://") {
		u, err := url.Parse(remote)
		if err != nil {
			return "", fmt.Errorf("parse ssh://: %w", err)
		}
		u.Scheme = "https"
		u.User = nil
		u.RawQuery, u.Fragment = "", ""
		u.Path = cleanPath(u.Path)
		u.Host = normalizeHostPort(u.Host, keepNonStandardPort)
		return hostSpecificPostprocess(u), nil
	}

	// SCP-like: [user@]host:path (host may be [IPv6])
	if scp := parseSCPLike(remote); scp != nil {
		host := scp.host
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1] // strip brackets for URL host
		}
		u := &url.URL{
			Scheme: "https",
			Host:   normalizeHostPort(host, keepNonStandardPort),
			Path:   cleanPath("/" + scp.path),
		}
		return hostSpecificPostprocess(u), nil
	}

	// Reject local paths/file remotes (out of scope)
	if strings.HasPrefix(low, "file://") ||
		strings.HasPrefix(remote, "/") ||
		strings.Contains(remote, `\`) ||
		looksLikeLocalPath(remote) {
		return "", fmt.Errorf("unsupported or local remote: %q", remote)
	}

	return "", fmt.Errorf("unrecognized git remote format: %q", remote)
}

// ------------------------ helpers ------------------------

func cleanPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/")
	p = "/" + p
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	return p
}

func normalizeHostPort(host string, keepNonStandardPort bool) string {
	host = stripDefaultPorts(host)
	if !keepNonStandardPort {
		host = dropPort(host)
	}
	return host
}

func stripDefaultPorts(host string) string {
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return host // no explicit port
	}
	if p == "22" || p == "443" {
		return h
	}
	return host
}

func dropPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// ------------------------ SCP-like parsing ------------------------

var scpLikeRx = regexp.MustCompile(`^(?:(?P<user>[^@]+)@)?(?P<host>\[[^\]]+\]|[^:]+):(?P<path>.+)$`)

type scpLike struct {
	user string
	host string
	path string
}

func parseSCPLike(s string) *scpLike {
	m := scpLikeRx.FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	return &scpLike{
		user: m[1],
		host: m[2],
		path: m[3],
	}
}

func looksLikeLocalPath(s string) bool {
	// Windows drive letter (C:\ or C:/)
	if len(s) >= 3 && s[1] == ':' && (s[2] == '\\' || s[2] == '/') {
		return true
	}
	// Paths like ".git" or "./repo"
	if strings.HasPrefix(s, ".") {
		return true
	}
	return false
}

// ------------------------ host-specific fixups --------------------

// hostSpecificPostprocess handles providers that require path remapping.
// GitHub/GitLab/Bitbucket: nothing special.
// Azure DevOps (modern + legacy): remap SSH shapes to canonical HTTPS.
func hostSpecificPostprocess(u *url.URL) string {
	hostLower := strings.ToLower(u.Host)

	switch {
	// Modern Azure DevOps SSH -> HTTPS mapping:
	//   SSH (SCP):   git@ssh.dev.azure.com:v3/{org}/{project}/{repo}
	//   SSH (URI):   ssh://git@ssh.dev.azure.com:22/v3/{org}/{project}/{repo}
	//   HTTPS out:   https://dev.azure.com/{org}/{project}/_git/{repo}
	case hostLower == "ssh.dev.azure.com":
		parts := splitPath(u.Path) // ["v3","org","project","repo"]
		if len(parts) >= 4 && parts[0] == "v3" {
			org, project, repo := parts[1], parts[2], parts[3]
			u.Host = "dev.azure.com"
			u.Path = fmt.Sprintf("/%s/%s/_git/%s", org, project, repo)
		}

	// Legacy Azure DevOps (Visual Studio):
	//   SSH (URI):   ssh://{org}@vs-ssh.visualstudio.com:22/{org}/{project}/_git/{repo}
	//   SSH (SCP):   {org}@vs-ssh.visualstudio.com:{org}/{project}/_git/{repo}
	//   HTTPS out:   https://{org}.visualstudio.com/{project}/_git/{repo}
	case strings.HasSuffix(hostLower, "vs-ssh.visualstudio.com"):
		parts := splitPath(u.Path) // ["org","project","_git","repo"]
		if len(parts) >= 4 && parts[2] == "_git" {
			org, project, repo := parts[0], parts[1], parts[3]
			u.Host = fmt.Sprintf("%s.visualstudio.com", org)
			u.Path = fmt.Sprintf("/%s/_git/%s", project, repo)
		}
	}

	return u.String()
}

func splitPath(p string) []string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}
