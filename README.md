# gogit-wrapper

Utilities for working with Git remotes in Go.

## Convert any Git remote to HTTPS

```go
import "github.com/devcoons/gogit-wrapper"

out, err := gitwrap.SshToHttps("git@bitbucket.org:organization/repo.git", false)
if err != nil {
    // handle
}
fmt.Println(out) // https://bitbucket.org/organization/repo.git
