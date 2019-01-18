// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

package main

import (
	"fmt"
	"os"
	"golang.org/x/sys/windows/svc"
	"log"
	"strings"
	"io"

)

func usage(errmsg string) {
	fmt.Fprintf(os.Stderr,
		"%s\n\n"+
			"usage: %s <command>\n"+
			"where <command> is one from:\n\n"+
			"generate 			[generate config file]\n"+
			"install            \t\t[install mdaemon log analyzer with generated..\n" +
			"					..or existing conf.json in root folder]\n" +
			"remove				[remove service]\n"+
			"debug				[run service without installing to..\n"+
			"					..windows service manager]\n" +
			"start				[start service]\n"+
			"stop				[stop service]\n",
		errmsg, os.Args[0])
	os.Exit(2)
}

func main() {

	const svcName = "Mdaemon Log Analyzer"
		writer := io.Writer(os.Stdout)

	isIntSess, err := svc.IsAnInteractiveSession()
	if err != nil {
		elog.Info(500, fmt.Sprintf("Fatal! Failed to determine if we are running in an interactive session: %s", err.Error()))
		log.Fatalf("failed to determine if we are running in an interactive session: %v", err)
	}
	if !isIntSess {
		runService(svcName, false)
		return
	}

	if len(os.Args) < 2 {
		usage("no command specified")
	}

	cmd := strings.ToLower(os.Args[1])
	switch cmd {
	case "help":
		usage("usage:")
	case "debug":
		fmt.Fprint(writer, "Running service in debug mode\n")
		runService(svcName, true)
		return
	case "generate":
		fmt.Fprint(writer, "Generating config file\n")
		generate()
	case "install":
			fmt.Fprint(writer, "Installing service\n")
			err = installService(svcName, "MdaemonLogAnalyzer")
	case "remove":
		fmt.Fprint(writer, "Removing service\n")
		err = removeService(svcName)
	case "start":
		fmt.Fprint(writer, "Starting service\n")
		err = startService(svcName)
	case "stop":
		fmt.Fprint(writer, "Stopping service\n")
		err = controlService(svcName, svc.Stop, svc.Stopped)
	default:
		usage(fmt.Sprintf("invalid command %s", cmd))
	}
	if err != nil {
		elog.Info(500, fmt.Sprintf("Fatal! Failed to %s %s: %s", cmd, svcName, err.Error()))
		log.Fatalf("failed to %s %s: %v", cmd, svcName, err)
	}
	return
}