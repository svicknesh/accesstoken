package accesstoken

import (
	"fmt"
	"os"
	"testing"
)

func TestGenerate(t *testing.T) {

	const (
		prefix = "abc"
	)

	output, err := Generate(prefix, Separator, RandomBytesLen)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(output)

	// create an incorrect token
	//len := len(prefix) + len(Separator)
	//output = output[:len] + "z" + output[len+1:]
	//fmt.Println(output)

	fmt.Println(IsChecksumOK(prefix, Separator, output))
}
