// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

package main

import (
	"fmt"
	"strings"
	"time"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"os"
	"log"
	"io/ioutil"
	"encoding/json"
	"strconv"
	"path/filepath"
)

var elog debug.Log

type myservice struct{}

func (m *myservice) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending}

		elog.Info(100, filepath.Dir(os.Args[0]))

	jsonfile := filepath.Dir(os.Args[0]) + "\\conf.json"

	if _, err := os.Stat(jsonfile); err != nil {
		println("\n")
		elog.Info(500, err.Error())
		log.Fatalf("Unable to find configuration file\nPlease, generate config using <generate> command\n ")
		return
	}

	data, err := ioutil.ReadFile(jsonfile)
    check(err)

	c := &Config{}
	err = json.Unmarshal(data, c)
	check(err)

	interval, err := strconv.ParseInt(c.ScanningInterval, 0, 0) //string to int
	if err != nil {
		log.Println(err)
		return
	}

	tick := time.Tick(time.Duration(interval) * time.Second)
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	fmt.Printf(strings.Join(args, "-"))
loop:
	for {
		scan_logs()
		select {
		case <-tick:
			fmt.Println("\n\nTick! New log analyze iteration start")
					case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				// Testing deadlock from https://code.google.com/p/winsvc/issues/detail?id=4
				time.Sleep(100 * time.Millisecond)
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				break loop
			default:
				println("\n")
				elog.Error(1, fmt.Sprintf("unexpected control request #%d", c))
			}
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	return
}

func runService(name string, isDebug bool) {
	var err error
	if isDebug {
		elog = debug.New(name)
	} else {
		elog, err = eventlog.Open(name)
		if err != nil {
			return
		}
	}
	defer elog.Close()

	println("\n")
	fmt.Println(fmt.Sprintf("Starting %s service ", name))
	run := svc.Run
	if isDebug {
		run = debug.Run
	}
	err = run(name, &myservice{})
	if err != nil {
		println("\n")
		elog.Error(200, fmt.Sprintf("%s service failed: %v", name, err))
		return
	}

	println("\n")
	elog.Info(1, fmt.Sprintf("%s service stopped", name))
}

func check(err error) {
	if err != nil {
		println("\n\n" + err.Error())
		elog.Info(500, fmt.Sprintf("Error occured: %v", err))
		os.Exit(0)
	}
}