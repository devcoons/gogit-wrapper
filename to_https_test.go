package gitwrap_test

import (
	"testing"

	gitwrap "github.com/devcoons/gogit-wrapper"
)

func TestSshToHttps_Common(t *testing.T) {
	tests := map[string]string{
		// Bitbucket
		"git@bitbucket.org:organization/repo.git":       "https://bitbucket.org/organization/repo.git",
		"ssh://git@bitbucket.org/organization/repo.git": "https://bitbucket.org/organization/repo.git",
		"http://bitbucket.org/organization/repo.git":    "https://bitbucket.org/organization/repo.git",
		"git://bitbucket.org/organization/repo.git":     "https://bitbucket.org/organization/repo.git",

		// GitHub / GitLab
		"git@github.com:org/repo.git":         "https://github.com/org/repo.git",
		"ssh://git@gitlab.com/group/proj.git": "https://gitlab.com/group/proj.git",

		// IPv6 SCP-like
		"git@[2001:db8::1]:org/repo.git": "https://[2001:db8::1]/org/repo.git",
	}

	for in, want := range tests {
		got, err := gitwrap.SshToHttps(in, false)
		if err != nil {
			t.Fatalf("%q: unexpected err: %v", in, err)
		}
		if got != want {
			t.Fatalf("%q:\n  got : %s\n  want: %s", in, got, want)
		}
	}
}

func TestSshToHttps_AzureDevOps(t *testing.T) {
	tests := map[string]string{
		// Modern ADO
		"git@ssh.dev.azure.com:v3/org/project/repo":          "https://dev.azure.com/org/project/_git/repo",
		"ssh://git@ssh.dev.azure.com:22/v3/org/project/repo": "https://dev.azure.com/org/project/_git/repo",

		// Legacy Visual Studio style
		"org@vs-ssh.visualstudio.com:org/project/_git/repo":          "https://org.visualstudio.com/project/_git/repo",
		"ssh://org@vs-ssh.visualstudio.com:22/org/project/_git/repo": "https://org.visualstudio.com/project/_git/repo",
	}

	for in, want := range tests {
		got, err := gitwrap.SshToHttps(in, false)
		if err != nil {
			t.Fatalf("%q: unexpected err: %v", in, err)
		}
		if got != want {
			t.Fatalf("%q:\n  got : %s\n  want: %s", in, got, want)
		}
	}
}

func TestSshToHttps_Rejections(t *testing.T) {
	bad := []string{
		"file:///tmp/repo.git",
		"/home/user/repo",
		"C:\\work\\repo",
		".git",
	}
	for _, in := range bad {
		if _, err := gitwrap.SshToHttps(in, false); err == nil {
			t.Fatalf("%q: expected error, got nil", in)
		}
	}
}
