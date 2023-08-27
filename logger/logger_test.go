package logger

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
)

func TestLogger(t *testing.T) {
	buff := bytes.NewBufferString("")
	lg := Func(func(format string, args ...interface{}) {
		fmt.Fprintf(buff, format, args...)
	})

	lg.Logf("blah %s %d something", "str", 123)

	if !strings.HasSuffix(buff.String(), "blah str 123 something") {
		t.Errorf("wrong log output: %s", buff.String())
	}
}

func TestStd(t *testing.T) {
	buff := bytes.NewBufferString("")
	log.SetOutput(buff)
	defer log.SetOutput(os.Stdout)

	Std.Logf("blah %s %d something", "str", 123)

	if !strings.HasSuffix(buff.String(), "blah str 123 something\n") {
		t.Errorf("wrong log output: %s", buff.String())
	}
}

func TestNoOp(t *testing.T) {
	buff := bytes.NewBufferString("")
	log.SetOutput(buff)
	defer log.SetOutput(os.Stdout)

	NoOp.Logf("blah %s %d something", "str", 123)

	if buff.String() != "" {
		t.Errorf("wrong log output: %s", buff.String())
	}
}
