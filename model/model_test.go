package model_test

import (
	"final/model"
	"fmt"
	"testing"
)

func TestModel(t *testing.T) {
	err := model.CombineGitTruffle("../secretReport/gitleaks/gitRepo/tuanvo1603/Hospital.json", "../secretReport/trufflehog/gitRepo/tuanvo1603/Hospital.json")
	fmt.Println("err: ", err)
}
