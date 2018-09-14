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
	"path/filepath"
	"log"
	"io/ioutil"
	"encoding/json"
	"strconv"
)

const PATH_SEPARATOR = "\\"

var elog debug.Log

type myservice struct{}

func (m *myservice) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending}

		ex, err := os.Executable()
		if err != nil {
			panic(err)
		}
		jsonfile := filepath.Dir(ex) + PATH_SEPARATOR + "conf.json"
		if err != nil {
			panic(err)
	}

	if _, err := os.Stat(jsonfile); err != nil {
		log.Fatalf("Unable to find configuration file\nPlease, generate config using <generate> command\n ")
		return
	}
	data, err := ioutil.ReadFile(jsonfile)
	if err != nil {
		log.Fatalln(err)
	}
	c := &Config{}
	err = json.Unmarshal(data, c)
	if err != nil {
		log.Println(err)
		return
	}

	interval, err := strconv.ParseInt(c.ScanningInterval, 0, 0) //string to int
	if err != nil {
		log.Println(err)
		return
	}

	fasttick := time.Tick(time.Duration(interval) * time.Second)
	slowtick := time.Tick(time.Duration(interval) * 3 * time.Second)
	tick := fasttick
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	fmt.Printf(strings.Join(args, "-"))
loop:
	for {
		scan_logs()
		select {
		case <-tick:
			fmt.Println("Tick! New log analyze iteration start")
					case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				// Testing deadlock from https://code.google.com/p/winsvc/issues/detail?id=4
				time.Sleep(100 * time.Millisecond)
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				break loop
			case svc.Pause:
				changes <- svc.Status{State: svc.Paused, Accepts: cmdsAccepted}
				tick = slowtick
			case svc.Continue:
				changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
				tick = fasttick
			default:
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

	fmt.Println(fmt.Sprintf("Starting %s service ", name))
	run := svc.Run
	if isDebug {
		run = debug.Run
	}
	err = run(name, &myservice{})
	if err != nil {
		elog.Error(200, fmt.Sprintf("%s service failed: %v", name, err))
		return
	}
	elog.Info(1, fmt.Sprintf("%s service stopped", name))
}