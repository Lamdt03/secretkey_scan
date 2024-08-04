package main

import (
	"bufio"
	"final/model"
	"final/src/detect"
	"final/src/repoOperation"
	"fmt"
	"github.com/panjf2000/ants"
	"os"
	"strings"
	"sync"
)

// get all git repository, repository in a organization or by a git username from a file
func getAllRepoFromFile(filepath string) []string {
	file, err := os.Open(filepath)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	fileScanner := bufio.NewScanner(file)
	fileScanner.Split(bufio.ScanLines)
	var rawRepos []string
	for fileScanner.Scan() {
		rawRepos = append(rawRepos, fileScanner.Text())
	}
	var repoList []string
	for _, rawRepo := range rawRepos {
		rawRepo = repoOperation.CleanRepo(rawRepo)
		if strings.Contains(rawRepo, "/") {
			repoList = append(repoList, rawRepo)
		} else {
			repos := repoOperation.GetOrgRepo(rawRepo)
			for _, repo := range repos {
				repoList = append(repoList, repo)
			}

		}
	}
	return repoList
}

func main() {
	var wg sync.WaitGroup
	resolveRepoCh := make(chan string, 100)
	gitleaksReportPathCh := make(chan string, 100)
	var gitleaksReportPathList []string
	truffReportPathCh := make(chan string, 100)
	var truffReportPathList []string
	fmt.Printf("enter file path: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	filepath := scanner.Text()
	repoList := getAllRepoFromFile(filepath)
	pool, _ := ants.NewPool(2) // change the pool size if you have more memory
	defer pool.Release()
	wg.Add(1)
	pool.Submit(func() {
		defer func() {
			wg.Done()
		}()
		for _, repo := range repoList {
			repoOperation.CloneRepo(repo)
			repoPath := "gitRepo/" + repo
			resolveRepoCh <- repoPath
		}
		for len(resolveRepoCh) != 0 {
			continue
		}
		close(resolveRepoCh)
	})

	for repo := range resolveRepoCh {

		wg.Add(1)
		err := pool.Submit(func() {
			defer func() {
				wg.Done()
			}()
			gitleaksReportPathCh <- detect.DetectByGitleaks(repo)
		})
		if err != nil {
			fmt.Println("error when generate goroutine: ", err)
		}

		wg.Add(1)
		err = pool.Submit(func() {
			defer func() {
				wg.Done()
			}()
			truffReportPathCh <- detect.DetectByTrufflehog(repo)
		})
		if err != nil {
			fmt.Println("error when generate goroutine: ", err)
		}
	}
	wg.Wait()
	fmt.Println("start analyzing")
	for gitleaksReportPath := range gitleaksReportPathCh {
		gitleaksReportPathList = append(gitleaksReportPathList, gitleaksReportPath)
		if len(gitleaksReportPathCh) == 0 {
			break
		}
	}
	close(gitleaksReportPathCh)
	for truffReportPath := range truffReportPathCh {
		truffReportPathList = append(gitleaksReportPathList, truffReportPath)
		if len(truffReportPathCh) == 0 {
			break
		}
	}
	close(truffReportPathCh)

	for _, truffReportPath := range truffReportPathList {
		for _, gitleaksReportPath := range gitleaksReportPathList {
			if truffReportPath == gitleaksReportPath {
				err := model.CombineGitTruffle("secretReport/gitleaks/"+gitleaksReportPath, "secretReport/trufflehog/"+gitleaksReportPath)
				if err != nil {
					fmt.Println("err when combine: " + gitleaksReportPath)
				} else {
					fmt.Println("analyzed: ", truffReportPath)
				}
				break
			}
		}
	}
}
