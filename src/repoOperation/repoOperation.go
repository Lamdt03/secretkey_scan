package repoOperation

import (
	"encoding/json"
	"fmt"
	"github.com/cli/go-gh"
	"strings"
)

func CloneRepo(repo string) {
	dst := "gitRepo/" + repo
	fmt.Println("cloning repo: ", repo)
	_, _, err := gh.Exec("repo", "clone", repo, dst)
	if err != nil {
		fmt.Println(err)
		if strings.Contains(err.Error(), "fetch-pack: unexpected disconnect while reading sideband packet") {
			CloneRepo(repo)
		}
	}
}

func CleanRepo(repo string) string {
	if strings.Contains(repo, "https://github.com/") {
		repo = strings.Replace(repo, "https://github.com/", "", 1)
	}
	if strings.HasSuffix(repo, "/") {
		repo = strings.TrimSuffix(repo, "/")
	}
	return repo
}

func GetOrgRepo(repo string) []string {
	listRepo, _, err := gh.Exec("repo", "list", repo, "--json", "nameWithOwner")
	data := listRepo.Bytes()
	var result []map[string]string
	json.Unmarshal(data, &result)
	if err != nil {
		fmt.Println(err)
	}
	var names []string
	for _, repo := range result {
		names = append(names, repo["nameWithOwner"])
	}
	return names
}
