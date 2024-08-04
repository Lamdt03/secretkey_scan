package detect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type Gitleaks struct {
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	StartColumn int      `json:"StartColumn"`
	EndColumn   int      `json:"EndColumn"`
	Match       string   `json:"Match"`
	Secret      string   `json:"Secret"`
	File        string   `json:"File"`
	SymlinkFile string   `json:"SymlinkFile"`
	Commit      string   `json:"Commit"`
	Entropy     float64  `json:"Entropy"`
	Author      string   `json:"Author"`
	Email       string   `json:"Email"`
	Date        string   `json:"Date"`
	Message     string   `json:"Message"`
	Tags        []string `json:"Tags"`
	RuleID      string   `json:"RuleID"`
	Fingerprint string   `json:"Fingerprint"`
}

// using gitleaks to detect secret key
func DetectByGitleaks(repo string) string {
	reportPath := "secretReport/gitleaks/" + repo + ".json"
	dirPath := filepath.Dir(reportPath)
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		fmt.Println(err)
	}
	_, err = os.Create(reportPath)
	if err != nil {
		fmt.Println(err)
	}

	cmd := exec.Command("gitleaks.exe", "detect", "--source", repo, "-f", "json", "-r", reportPath, "--no-color", "--no-banner")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		fmt.Println(err)
		fmt.Println(stderr.String())
	}
	fmt.Println("scan success by gitleaks: ", repo)
	return repo + ".json"
}

// read a gitleaks secret report file in json format into a map of gitleaks type with key is git commit id
func ReadGitleaksSecret(filepath string) (map[string]Gitleaks, error) {
	reportFile, err := os.Open(filepath)
	defer reportFile.Close()
	if err != nil {
		return nil, err
	}
	rawSecret, err := os.ReadFile(filepath)
	var gitleaksSecret []Gitleaks
	gitleaksSecretMap := make(map[string]Gitleaks)
	err = json.Unmarshal(rawSecret, &gitleaksSecret)
	if err != nil {
		return gitleaksSecretMap, err
	}
	for _, secret := range gitleaksSecret {
		gitleaksSecretMap[secret.Commit] = secret
	}
	return gitleaksSecretMap, nil
}
