// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.


package main

import (
	"os"
	"log"
	"io/ioutil"
	"encoding/json"
	"strconv"
	"time"
	"fmt"
)

func main() {

	jsonfile := "./conf.json"

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

	tick := time.Tick(time.Duration(interval) * time.Second)

	for {
		scan_logs()
		select {
		case <-tick:
			timestamp := time.Now()
			p := fmt.Printf
			p(timestamp.Format(time.RFC3339Nano))
			fmt.Printf( "\n\n%s ... Tick! New log analyze iteration start\n", timestamp )
		}
	}
}