package detect_test

import (
	"final/src/detect"
	"fmt"
	"testing"
)

func TestDetection(t *testing.T) {
	trufflehogSecretMap, err := detect.ReadTrufflehogSecret("../../secretReport/trufflehog/gitRepo/Lamdt03/ISD.ICT.20232.23.json")
	fmt.Println("map0: ", trufflehogSecretMap)
	fmt.Println("err0: ", err)
	gitleaksSecretMap, err := detect.ReadGitleaksSecret("../../secretReport/gitleaks/gitRepo/Lamdt03/ISD.ICT.20232.23.json")
	fmt.Println("map1: ", gitleaksSecretMap)
	fmt.Println("err1: ", err)
}
