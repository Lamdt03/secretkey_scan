package model

import (
	"encoding/json"
	"final/src/detect"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type SecretKey struct {
	Email       string `json:"email"`
	Commit      string `json:"commit"`
	File        string `json:"file"`
	Timestamp   string `json:"timestamp"`
	Message     string `json:"message"`
	Secret      string `json:"secret"`
	Location    string `json:"location"`
	Description string `json:"description"`
	IsVerified  bool   `json:"isVerified"`
	DetectedBy  string `json:"detectedBy"`
}

// combine secret key found by trufflehog and gitleaks
func CombineGitTruffle(gitleaksPath, trufflehogPath string) error {
	gitSecretMap, err := detect.ReadGitleaksSecret(gitleaksPath)
	if err != nil {
		return err
	}

	truffSecretMap, err := detect.ReadTrufflehogSecret(trufflehogPath)
	if err != nil {
		return err
	}
	var secretKey SecretKey
	var secretKeyList []SecretKey
	gitRepo := strings.TrimPrefix(gitleaksPath, "secretReport/gitleaks/gitRepo/")
	gitRepo = strings.TrimSuffix(gitRepo, ".json")
	url := "https://github.com/" + gitRepo + "/blob/"
	for commit, gitleaksSecret := range gitSecretMap {
		truffleSecret, exist := truffSecretMap[commit]
		if exist {
			secretKey.Email = gitleaksSecret.Email
			secretKey.Commit = gitleaksSecret.Commit
			secretKey.IsVerified = true
			secretKey.Description = gitleaksSecret.Description
			gitleaksSecret.Date = strings.ReplaceAll(gitleaksSecret.Date, "T", " ")
			gitleaksSecret.Date = strings.ReplaceAll(gitleaksSecret.Date, "Z", "")
			secretKey.Timestamp = gitleaksSecret.Date
			secretKey.Message = truffleSecret.ExtraData.Message + " " + gitleaksSecret.Message
			secretKey.DetectedBy = "trufflehog + gitleaks"
			secretKey.File = gitleaksSecret.File
			secretKey.Location = url + secretKey.Commit + "/" + gitleaksSecret.File + "#L" + strconv.Itoa(gitleaksSecret.StartLine)
			secretKey.Secret = gitleaksSecret.Secret
		} else {
			secretKey.Email = gitleaksSecret.Email
			secretKey.Commit = gitleaksSecret.Commit
			secretKey.IsVerified = false
			secretKey.Description = gitleaksSecret.Description
			gitleaksSecret.Date = strings.ReplaceAll(gitleaksSecret.Date, "T", " ")
			gitleaksSecret.Date = strings.ReplaceAll(gitleaksSecret.Date, "Z", "")
			secretKey.Timestamp = gitleaksSecret.Date
			secretKey.Message = gitleaksSecret.Message
			secretKey.DetectedBy = "gitleaks"
			secretKey.File = gitleaksSecret.File
			secretKey.Location = url + secretKey.Commit + "/" + gitleaksSecret.File + "#L" + strconv.Itoa(gitleaksSecret.StartLine)
			secretKey.Secret = gitleaksSecret.Secret
		}
		secretKeyList = append(secretKeyList, secretKey)
	}
	for commit, truffSecret := range truffSecretMap {
		_, exist := gitSecretMap[commit]
		if !exist {
			secretKey.Commit = truffSecret.SourceMetadata.Data.Git.Commit
			secretKey.Secret = truffSecret.Raw
			start := strings.Index(truffSecret.SourceMetadata.Data.Git.Email, "<") + 1
			end := strings.LastIndex(truffSecret.SourceMetadata.Data.Git.Email, ">")
			if start > 0 && end > -1 {
				secretKey.Email = truffSecret.SourceMetadata.Data.Git.Email[start:end]
			} else {
				secretKey.Email = truffSecret.SourceMetadata.Data.Git.Email
			}

			secretKey.Message = truffSecret.ExtraData.Message
			secretKey.DetectedBy = "trufflehog"
			secretKey.File = truffSecret.SourceMetadata.Data.Git.File
			secretKey.IsVerified = truffSecret.Verified
			secretKey.Description = truffSecret.DetectorName + " " + truffSecret.DecoderName
			end = strings.Index(truffSecret.SourceMetadata.Data.Git.Timestamp, "+")
			if end != -1 {
				secretKey.Timestamp = truffSecret.SourceMetadata.Data.Git.Timestamp[:end-1]
			} else {
				secretKey.Timestamp = truffSecret.SourceMetadata.Data.Git.Timestamp
			}
			secretKey.Location = url + secretKey.Commit + "/" + truffSecret.SourceMetadata.Data.Git.File + "#L" + strconv.Itoa(truffSecret.SourceMetadata.Data.Git.Line)
			secretKeyList = append(secretKeyList, secretKey)
		}
	}
	_, err = os.Create("secretReport/" + filepath.Base(gitleaksPath))
	if err != nil {
		return err
	}
	newSecretKeyList := removeDuplicateKey(secretKeyList)
	for _, s := range newSecretKeyList {
		err = WriteSecretToJson(s, "secretReport/"+filepath.Base(gitleaksPath))
		if err != nil {
			fmt.Println("cannot write to json: secretReport/", filepath.Base(gitleaksPath))
			return err
		}
	}
	return nil
}

func WriteSecretToJson(secretKey SecretKey, filepath string) error {
	jsonSecret, err := json.Marshal(secretKey)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_WRONLY, 0644)
	defer file.Close()
	_, err = fmt.Fprintln(file, string(jsonSecret))
	if err != nil {
		return err
	}
	return nil
}

func removeDuplicateKey(secretKeyList []SecretKey) []SecretKey {
	isDuplicate := make(map[string]SecretKey)
	var newSecretKeyList []SecretKey
	for _, secretKey := range secretKeyList {
		isDuplicate[secretKey.Commit] = secretKey
	}
	for i := 0; i < len(secretKeyList)-1; i++ {
		for j := i + 1; j < len(secretKeyList); j++ {
			_, exist := isDuplicate[secretKeyList[j].Commit]
			if secretKeyList[i].Secret == secretKeyList[j].Secret && exist {
				secretKeyList[i].Location = secretKeyList[i].Location + "," + secretKeyList[j].Location
				delete(isDuplicate, secretKeyList[j].Commit)
			}
		}
	}
	for _, secretKey := range secretKeyList {
		_, exist := isDuplicate[secretKey.Commit]
		if exist {
			newSecretKeyList = append(newSecretKeyList, secretKey)
		}
	}
	return newSecretKeyList
}
