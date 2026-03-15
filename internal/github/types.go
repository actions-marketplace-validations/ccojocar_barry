package github

// PRData holds metadata about a pull request.
type PRData struct {
	Number       int
	Title        string
	Body         string
	Author       string
	HeadSHA      string
	RepoFullName string
	Additions    int
	Deletions    int
	ChangedFiles int
	Files        []PRFile
}

// PRFile describes a single file changed in the PR.
type PRFile struct {
	Filename  string
	Status    string // added, removed, modified, renamed
	Additions int
	Deletions int
	Patch     string
}

// ReviewComment is a single inline comment to post on a PR.
type ReviewComment struct {
	Path string
	Line int
	Body string
}
