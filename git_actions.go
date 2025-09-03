package gitwrap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/plumbing/transport"
	httpgit "github.com/go-git/go-git/v5/plumbing/transport/http"
)

var (
	cloneMutex           sync.Mutex
	blackListMutex       sync.Mutex
	checkedListMutex     sync.Mutex
	blackListedRepos     map[string]time.Time
	checkedRecentlyRepos map[string]time.Time
)

type RepoSyncResult string

const (
	RepoNewlyCloned RepoSyncResult = "newly_cloned"
	RepoRefreshed   RepoSyncResult = "refreshed"
	RepoNoUpdates   RepoSyncResult = "no_updates"
	Unknown         RepoSyncResult = "unknown"
)

type RepoSubmodulesReport struct {
	Branch     string
	Commit     string
	Submodules []SubmoduleInfo
}

type gmEntry struct {
	Name string
	Path string
	URL  string
}

type SubmoduleInfo struct {
	Name           string
	Path           string
	Commit         string
	DeclaredURL    string
	NormalizedURL  string
	DeclaredScheme string
	Declared       bool
	Configured     bool
}

type BranchListOptions struct {
	IncludeLocal  bool
	IncludeRemote bool
	RemoteName    string
	ActiveSince   *time.Time
	MaxCommits    int
}

type CommitInfo struct {
	Hash   string
	Author string
	Email  string
	When   time.Time
	Title  string
}

type BranchInfo struct {
	Name       string
	IsRemote   bool
	Remote     string
	HeadHash   string
	HeadWhen   time.Time
	CommitList []CommitInfo
}

type TagInfo struct {
	Name      string
	CommitID  string
	CommitAt  time.Time
	Annotated bool
	Tagger    string
	Message   string
	Branches  []string
}

// CloneOrSyncRepo clones a repository to dir or fetches updates if a valid repo already exists.
func CloneOrSyncRepo(url string, dir string, user *string, token *string, progress io.Writer) (RepoSyncResult, *git.Repository, error) {
	if progress == nil {
		progress = io.Discard
	}
	if !strings.Contains(url, "git") {
		return Unknown, nil, fmt.Errorf("fatal error: [SyncOrUpdateRepo] (%s) Repo Url is invalid", url)
	}
	if _, err := SshToHttps(url, false); err != nil {
		return Unknown, nil, fmt.Errorf("invalid repo URL %q: %w", url, err)
	}
	folderValid := func() (bool, error) {
		if !folderExists(dir) {
			return false, fmt.Errorf("[SyncOrUpdateRepo] (%s) Folder does not exist: %s", url, dir)
		}
		repo, err := git.PlainOpen(dir)
		if err != nil {
			return false, fmt.Errorf("[SyncOrUpdateRepo] (%s) Could not open git repo at %s: %v", url, dir, err)
		}
		if _, err := repo.Head(); err != nil {
			return false, fmt.Errorf("[SyncOrUpdateRepo] (%s) Repo folder is corrupt or incomplete: %v", url, err)
		}
		return true, nil
	}
	is_folder_valid, _ := folderValid()
	if is_folder_valid {
		repo, err := git.PlainOpen(dir)
		if err != nil {
			blackListMutex.Lock()
			if blackListedRepos == nil {
				blackListedRepos = make(map[string]time.Time)
			}
			if _, exists := blackListedRepos[url]; !exists {
				blackListedRepos[url] = time.Now().UTC().Add(1 * time.Hour)
			}
			blackListMutex.Unlock()
			return Unknown, nil, err
		}
		if !isRepoCheckedRecently(url) {
			cloneMutex.Lock()
			updated, err := checkAndFetchUpdates(repo, user, token, progress)
			cloneMutex.Unlock()
			if err != nil {
				return Unknown, nil, fmt.Errorf("[SyncOrUpdateRepo] (%s) Failed to check for updates: %v", url, err)
			}
			if updated {
				return RepoRefreshed, repo, nil
			}
			appendToRepoCheckedRecently(url)
		}
		return RepoNoUpdates, repo, nil
	}
	if folderExists(dir) {
		_ = os.RemoveAll(dir)
	}
	cloneMutex.Lock()

	var auth transport.AuthMethod
	if user != nil && token != nil {
		auth = &httpgit.BasicAuth{
			Username: *user,
			Password: *token,
		}
	}

	repo, err := git.PlainClone(dir, false, &git.CloneOptions{
		URL:      url,
		Depth:    0,
		Tags:     git.AllTags,
		Auth:     auth,
		Progress: progress,
	})
	cloneMutex.Unlock()
	if err != nil {
		return "", nil, fmt.Errorf("[SyncOrUpdateRepo] (%s) Failed to clone repo: %v", url, err)
	}
	appendToRepoCheckedRecently(url)
	return RepoNewlyCloned, repo, nil
}

// ListSubmodulesReport returns branch name, head commit and discovered submodules without requiring init.
func ListSubmodulesReport(repoDir string) (*RepoSubmodulesReport, error) {
	r, err := git.PlainOpen(repoDir)
	if err != nil {
		return nil, fmt.Errorf("open repo: %w", err)
	}
	headRef, err := r.Head()
	if err != nil {
		return nil, fmt.Errorf("get HEAD: %w", err)
	}
	headCommit, err := r.CommitObject(headRef.Hash())
	if err != nil {
		return nil, fmt.Errorf("read HEAD commit: %w", err)
	}
	report := RepoSubmodulesReport{
		Branch: headRef.Name().Short(),
		Commit: headRef.Hash().String(),
	}
	tree, err := headCommit.Tree()
	if err != nil {
		return nil, fmt.Errorf("read HEAD tree: %w", err)
	}
	foundByPath := map[string]*SubmoduleInfo{}
	if err := walkTreeForGitlinks(r, tree, "", foundByPath); err != nil {
		return nil, fmt.Errorf("walk tree: %w", err)
	}
	byPathGM := map[string]gmEntry{}
	gitmodulesPath := filepath.Join(repoDir, ".gitmodules")
	if f, err := os.Open(gitmodulesPath); err == nil {
		defer f.Close()
		if cfg, err := config.ReadConfig(f); err == nil && len(cfg.Submodules) > 0 {
			for name, sm := range cfg.Submodules {
				p := filepath.ToSlash(sm.Path)
				byPathGM[p] = gmEntry{Name: name, Path: p, URL: sm.URL}
			}
		} else {
			_ = parseGitmodulesLoose(f, byPathGM)
		}
	}
	cfg, _ := r.Config()
	configuredByPath := map[string]config.Submodule{}
	if cfg != nil && len(cfg.Submodules) > 0 {
		for name, sm := range cfg.Submodules {
			p := filepath.ToSlash(sm.Path)
			configuredByPath[p] = config.Submodule{
				Name:   name,
				Path:   p,
				URL:    sm.URL,
				Branch: sm.Branch,
			}
		}
	}
	parentURL := ""
	if rem, err := r.Remote("origin"); err == nil && rem != nil && len(rem.Config().URLs) > 0 {
		parentURL = rem.Config().URLs[0]
	}
	resolveURL := func(u string) string {
		if u == "" {
			return u
		}
		if strings.Contains(u, "://") || looksLikeScp(u) {
			return u
		}
		if parentURL == "" {
			return u
		}
		if abs, ok := resolveRelativeURL(parentURL, u); ok {
			return abs
		}
		return u
	}
	for p, info := range foundByPath {
		if gm, ok := byPathGM[p]; ok {
			if gm.Name != "" {
				info.Name = gm.Name
			}
			if gm.URL != "" {
				info.DeclaredURL = resolveURL(gm.URL)
			}
			info.Declared = true
		}
		if sm, ok := configuredByPath[p]; ok {
			if info.Name == "" {
				info.Name = sm.Name
			}
			if info.DeclaredURL == "" && sm.URL != "" {
				info.DeclaredURL = resolveURL(sm.URL)
			}
			info.Configured = true
		}
		finalizeURLs(info)
	}
	for p, gm := range byPathGM {
		if _, ok := foundByPath[p]; ok {
			continue
		}
		info := &SubmoduleInfo{
			Name:        firstNonEmpty(gm.Name, gm.Path),
			Path:        p,
			DeclaredURL: resolveURL(gm.URL),
			Declared:    true,
		}
		if sm, ok := configuredByPath[p]; ok {
			info.Configured = true
			if info.DeclaredURL == "" && sm.URL != "" {
				info.DeclaredURL = resolveURL(sm.URL)
			}
		}
		finalizeURLs(info)
		foundByPath[p] = info
	}
	report.Submodules = make([]SubmoduleInfo, 0, len(foundByPath))
	for _, v := range foundByPath {
		if v.Name == "" {
			v.Name = v.Path
		}
		report.Submodules = append(report.Submodules, *v)
	}
	return &report, nil
}

// ListTags returns all tags in the repo and optionally the branches that contain each tag’s commit.
func ListTags(repoDir string, includeBranches bool) ([]TagInfo, error) {
	r, err := git.PlainOpen(repoDir)
	if err != nil {
		return nil, fmt.Errorf("open repo: %w", err)
	}
	var commitBranches map[plumbing.Hash][]string
	if includeBranches {
		commitBranches, _ = buildCommitBranchesMapForTags(r)
	}
	var tags []TagInfo
	refs, err := r.References()
	if err != nil {
		return nil, fmt.Errorf("list refs: %w", err)
	}
	err = refs.ForEach(func(ref *plumbing.Reference) error {
		if !ref.Name().IsTag() {
			return nil
		}
		obj, err := r.Object(plumbing.AnyObject, ref.Hash())
		if err != nil {
			return nil
		}
		var (
			commit    *object.Commit
			annotated bool
			tagger    string
			message   string
		)
		switch o := obj.(type) {
		case *object.Tag:
			annotated = true
			tagger = o.Tagger.Name
			message = firstLine(o.Message)
			c, err := r.CommitObject(o.Target)
			if err != nil {
				return nil
			}
			commit = c
		case *object.Commit:
			annotated = false
			commit = o
		default:
			return nil
		}
		ti := TagInfo{
			Name:      ref.Name().Short(),
			CommitID:  commit.Hash.String(),
			CommitAt:  commit.Committer.When.UTC(),
			Annotated: annotated,
			Tagger:    tagger,
			Message:   message,
		}
		if includeBranches && commitBranches != nil {
			ti.Branches = append(ti.Branches, commitBranches[commit.Hash]...)
			sort.Strings(ti.Branches)
		}
		tags = append(tags, ti)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i].CommitAt.After(tags[j].CommitAt) })
	return tags, nil
}

// ListBranchesWithCommits returns branches with optional activity filtering and per-branch commit lists.
func ListBranchesWithCommits(repoDir string, opts *BranchListOptions) ([]BranchInfo, error) {
	r, err := git.PlainOpen(repoDir)
	if err != nil {
		return nil, fmt.Errorf("open repo: %w", err)
	}
	if opts == nil {
		opts = &BranchListOptions{IncludeLocal: true}
	}
	var out []BranchInfo
	addBranch := func(ref *plumbing.Reference, isRemote bool, remoteName string) error {
		headHash := ref.Hash()
		commit, err := r.CommitObject(headHash)
		if err != nil {
			return nil
		}
		headWhen := commit.Committer.When
		if opts.ActiveSince != nil && headWhen.Before(*opts.ActiveSince) {
			return nil
		}
		bi := BranchInfo{
			Name:     ref.Name().Short(),
			IsRemote: isRemote,
			Remote:   remoteName,
			HeadHash: headHash.String(),
			HeadWhen: headWhen,
		}
		logIt, err := r.Log(&git.LogOptions{From: headHash})
		if err == nil {
			count := 0
			_ = logIt.ForEach(func(c *object.Commit) error {
				bi.CommitList = append(bi.CommitList, CommitInfo{
					Hash:   c.Hash.String(),
					Author: c.Author.Name,
					Email:  c.Author.Email,
					When:   c.Author.When,
					Title:  firstLine(c.Message),
				})
				count++
				if opts.MaxCommits > 0 && count >= opts.MaxCommits {
					return storer.ErrStop
				}
				return nil
			})
		}
		out = append(out, bi)
		return nil
	}
	if opts.IncludeLocal {
		it, err := r.Branches()
		if err == nil {
			_ = it.ForEach(func(ref *plumbing.Reference) error {
				return addBranch(ref, false, "")
			})
		}
	}
	if opts.IncludeRemote {
		refs, err := r.References()
		if err == nil {
			_ = refs.ForEach(func(ref *plumbing.Reference) error {
				n := ref.Name()
				if !n.IsRemote() {
					return nil
				}
				if n.String() == "refs/remotes/"+opts.RemoteName+"/HEAD" {
					return nil
				}
				remote := remoteOf(n)
				if opts.RemoteName != "" && remote != opts.RemoteName {
					return nil
				}
				return addBranch(ref, true, remote)
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].HeadWhen.After(out[j].HeadWhen)
	})
	return out, nil
}

// buildCommitBranchesMapForTags builds a commit->branches map over remote branches.
func buildCommitBranchesMapForTags(r *git.Repository) (map[plumbing.Hash][]string, error) {
	m := make(map[plumbing.Hash][]string)
	refs, err := r.References()
	if err != nil {
		return nil, err
	}
	err = refs.ForEach(func(ref *plumbing.Reference) error {
		if !ref.Name().IsRemote() || strings.HasSuffix(ref.Name().String(), "/HEAD") {
			return nil
		}
		br := ref.Name().Short()
		head, err := r.CommitObject(ref.Hash())
		if err != nil {
			return nil
		}
		iter := object.NewCommitPreorderIter(head, nil, nil)
		return iter.ForEach(func(c *object.Commit) error {
			m[c.Hash] = append(m[c.Hash], br)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

// firstLine returns the first line of a string trimmed of whitespace.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// remoteOf extracts the remote name from a refs/remotes/<remote>/<branch> ref.
func remoteOf(n plumbing.ReferenceName) string {
	const pfx = "refs/remotes/"
	s := n.String()
	if !strings.HasPrefix(s, pfx) {
		return ""
	}
	rest := strings.TrimPrefix(s, pfx)
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[:i]
	}
	return ""
}

// isRepoCheckedRecently reports whether a repo URL was checked within its TTL.
func isRepoCheckedRecently(url string) bool {
	checkedListMutex.Lock()
	expiry, exists := checkedRecentlyRepos[url]
	checkedListMutex.Unlock()
	if !exists {
		return false
	}
	if time.Now().After(expiry) {
		checkedListMutex.Lock()
		delete(checkedRecentlyRepos, url)
		checkedListMutex.Unlock()
		return false
	}
	return true
}

// appendToRepoCheckedRecently records a repo URL as checked with a TTL.
func appendToRepoCheckedRecently(url string) {
	checkedListMutex.Lock()
	if checkedRecentlyRepos == nil {
		checkedRecentlyRepos = make(map[string]time.Time)
	}
	if _, exists := checkedRecentlyRepos[url]; !exists {
		checkedRecentlyRepos[url] = time.Now().UTC().Add(1 * time.Hour)
	}
	checkedListMutex.Unlock()
}

// folderExists returns true if the given path exists on disk.
func folderExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// checkAndFetchUpdates detects remote updates and fetches when necessary.
func checkAndFetchUpdates(repo *git.Repository, user *string, token *string, progress io.Writer) (bool, error) {
	if progress == nil {
		progress = io.Discard
	}
	remote, err := repo.Remote("origin")
	if err != nil {
		return false, err
	}

	var auth transport.AuthMethod
	if user != nil && token != nil {
		auth = &httpgit.BasicAuth{
			Username: *user,
			Password: *token,
		}
	}

	refs, err := remote.List(&git.ListOptions{Auth: auth})
	if err != nil {
		return false, err
	}
	hasUpdates := false
	for _, ref := range refs {
		if !ref.Name().IsBranch() {
			continue
		}
		localRefName := plumbing.NewRemoteReferenceName("origin", ref.Name().Short())
		localRef, err := repo.Reference(localRefName, true)
		if err != nil {
			hasUpdates = true
			break
		}
		if localRef.Hash() != ref.Hash() {
			hasUpdates = true
			break
		}
	}
	if !hasUpdates {
		return false, nil
	}
	err = repo.FetchContext(context.Background(), &git.FetchOptions{
		RemoteName: "origin",
		Progress:   progress,
		Tags:       git.AllTags,
		Force:      true,
		Auth:       auth,
	})
	if errors.Is(err, git.NoErrAlreadyUpToDate) {
		return false, nil
	} else if err != nil && !errors.Is(err, transport.ErrEmptyRemoteRepository) {
		return false, err
	}
	return true, nil
}

// walkTreeForGitlinks walks a tree and records gitlink (submodule) entries in out.
func walkTreeForGitlinks(r *git.Repository, t *object.Tree, prefix string, out map[string]*SubmoduleInfo) error {
	for _, e := range t.Entries {
		switch e.Mode {
		case filemode.Submodule:
			path := filepath.ToSlash(filepath.Join(prefix, e.Name))
			out[path] = &SubmoduleInfo{
				Name:   path,
				Path:   path,
				Commit: e.Hash.String(),
			}
		case filemode.Dir:
			child, err := r.TreeObject(e.Hash)
			if err != nil {
				continue
			}
			if err := walkTreeForGitlinks(r, child, filepath.Join(prefix, e.Name), out); err != nil {
				return err
			}
		default:
		}
	}
	return nil
}

// parseGitmodulesLoose parses a .gitmodules file into a path->entry map tolerantly.
func parseGitmodulesLoose(f *os.File, byPath map[string]gmEntry) error {
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	sectionRe := regexp.MustCompile(`^\s*\[submodule\s*"([^"]*)"\]\s*$`)
	kvRe := regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(.*?)\s*$`)
	var curName, curPath, curURL string
	flush := func() {
		if curPath != "" {
			byPath[curPath] = gmEntry{
				Name: curName,
				Path: curPath,
				URL:  curURL,
			}
		}
		curName, curPath, curURL = "", "", ""
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if m := sectionRe.FindStringSubmatch(line); m != nil {
			flush()
			curName = m[1]
			continue
		}
		if m := kvRe.FindStringSubmatch(line); m != nil {
			key := strings.ToLower(m[1])
			val := strings.TrimSpace(m[2])
			switch key {
			case "path":
				curPath = filepath.ToSlash(val)
			case "url":
				curURL = val
			}
		}
	}
	flush()
	return sc.Err()
}

// looksLikeScp reports whether a URL string appears to be scp-like SSH.
func looksLikeScp(s string) bool {
	if strings.Contains(s, "@") && strings.Contains(s, ":") {
		return true
	}
	if !strings.Contains(s, "://") && strings.Count(s, ":") == 1 && !strings.Contains(s, "/") {
		return true
	}
	return false
}

// resolveRelativeURL resolves a relative submodule URL against the parent remote URL.
func resolveRelativeURL(parent, rel string) (string, bool) {
	if strings.Contains(parent, "://") {
		pu, err := url.Parse(parent)
		if err != nil {
			return "", false
		}
		pp := strings.TrimSuffix(pu.Path, ".git")
		parts := strings.Split(strings.TrimPrefix(pp, "/"), "/")
		if len(parts) < 2 {
			return "", false
		}
		base := &url.URL{
			Scheme: pu.Scheme,
			Host:   pu.Host,
			Path:   "/" + parts[0] + "/",
		}
		ref, err := url.Parse(rel)
		if err != nil {
			return "", false
		}
		abs := base.ResolveReference(ref)
		return strings.TrimSuffix(abs.String(), "/"), true
	}
	if i := strings.Index(parent, ":"); i > -1 && strings.Contains(parent[:i], "@") {
		host := parent[:i]
		return host + ":" + strings.TrimPrefix(rel, "./"), true
	}
	return "", false
}

// firstNonEmpty returns the first non-empty string among a and b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// classifyScheme classifies a URL as SSH or HTTPS when possible.
func classifyScheme(u string) string {
	uu := strings.ToLower(u)
	switch {
	case strings.HasPrefix(uu, "http://"), strings.HasPrefix(uu, "https://"):
		return "HTTPS"
	case strings.HasPrefix(uu, "ssh://"), looksLikeScp(u):
		return "SSH"
	default:
		return ""
	}
}

// finalizeURLs computes DeclaredScheme and NormalizedURL fields for a submodule entry.
func finalizeURLs(info *SubmoduleInfo) {
	if info.DeclaredURL != "" {
		info.DeclaredScheme = classifyScheme(info.DeclaredURL)
		if norm, err := SshToHttps(info.DeclaredURL, false); err == nil {
			info.NormalizedURL = norm
		}
	}
}
