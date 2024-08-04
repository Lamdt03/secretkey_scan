package detect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type SourceMetadata struct {
	Data struct {
		Git struct {
			Commit     string `json:"commit"`
			File       string `json:"file"`
			Email      string `json:"email"`
			Repository string `json:"repository"`
			Timestamp  string `json:"timestamp"`
			Line       int    `json:"line"`
		} `json:"Git"`
	} `json:"Data"`
}

type Trufflehog struct {
	SourceMetadata    SourceMetadata `json:"SourceMetadata"`
	SourceID          int            `json:"SourceID"`
	SourceType        int            `json:"SourceType"`
	SourceName        string         `json:"SourceName"`
	DetectorType      int            `json:"DetectorType"`
	DetectorName      string         `json:"DetectorName"`
	DecoderName       string         `json:"DecoderName"`
	Verified          bool           `json:"Verified"`
	VerificationError string         `json:"VerificationError"`
	Raw               string         `json:"Raw"`
	RawV2             string         `json:"RawV2"`
	Redacted          string         `json:"Redacted"`
	ExtraData         struct {
		Account      string `json:"account"`
		Arn          string `json:"arn"`
		IsCanary     string `json:"is_canary"`
		Message      string `json:"message"`
		ResourceType string `json:"resource_type"`
	} `json:"ExtraData"`
	StructuredData interface{} `json:"StructuredData"`
}

// using trufflehog to detect secret key
func DetectByTrufflehog(repo string) string {
	reportPath := "secretReport/trufflehog/" + repo + ".json"
	dirPath := filepath.Dir(reportPath)
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		fmt.Println(err)
	}

	outputFile, err := os.Create(reportPath)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	defer outputFile.Close()

	repo = "file://" + repo
	cmd := exec.Command("trufflehog", "git", repo, "-j")
	var stderr bytes.Buffer
	cmd.Stdout = outputFile
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		fmt.Println(err)
		fmt.Println(stderr.String())
	}
	fmt.Println("scan success by truffehog: ", repo)
	return repo + ".json"
}

// read a trufflehog secret report file in json format into a map of trufflehog type with key is git commit id
func ReadTrufflehogSecret(filepath string) (map[string]Trufflehog, error) {
	reportFile, err := os.Open(filepath)
	defer reportFile.Close()
	if err != nil {
		return nil, err
	}
	rawSecret, err := os.ReadFile(filepath)
	jsonStr := string(rawSecret)
	jsonStr = strings.TrimRight(jsonStr, "\n")
	jsonStr = "[" + strings.TrimSpace(strings.ReplaceAll(jsonStr, "\n", ",")) + "]"
	var trufflehogSecret []Trufflehog
	trufflehogSecretMap := make(map[string]Trufflehog)
	err = json.Unmarshal([]byte(jsonStr), &trufflehogSecret)
	if err != nil {
		return trufflehogSecretMap, err
	}
	for _, secret := range trufflehogSecret {
		trufflehogSecretMap[secret.SourceMetadata.Data.Git.Commit] = secret
	}
	return trufflehogSecretMap, nil
}

// get start column postion of secret key
func GetSecretLocation(filepath string, line int, secret string) int {
	content, err := os.ReadFile(filepath)
	if err != nil {
		fmt.Println("cannot read file: ", err)
		return -1
	}
	lines := strings.Split(string(content), "\n")
	if len(lines) < line {
		fmt.Println("wrong location")
		return -1
	}
	position := strings.Index(lines[line-1], secret)
	return position
}
