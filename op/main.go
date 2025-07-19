package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/ethereum-optimism/optimism/op-devstack/presets"
)

func main() {
	presets.DoMain(testingM{}, presets.WithMinimal())
}

type testingM struct{}

var _ presets.TestingM = testingM{}

func (t testingM) Run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()
	<-ctx.Done()
	return 0
}
