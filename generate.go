package main

import (
	"bufio"
	"os"
	"strings"
	"fmt"
	"log"
	"encoding/json"
	"path/filepath"
)

func generate () {

	jsonfile := filepath.Dir(os.Args[0]) +  "\\conf.json"

	reader := bufio.NewReader(os.Stdin)
	if fStat, err := os.Stat(jsonfile); err == nil && !fStat.IsDir() {
		fmt.Printf("Configuration file (%s) exists, overwrite? (y/n): ", jsonfile)
		if r, _ := reader.ReadString('\n'); strings.ToLower(strings.TrimSpace(r)) != "y" {
			return
		}
		err := os.Remove(jsonfile)
		if err != nil {
			log.Fatalln(err)
		}
	}
	f, err := os.OpenFile(jsonfile, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)

	c := &Config{
		From: EmailStruct{
			Name:  ask("Enter \"From\" name:\t\t"),
			Email: ask("Enter \"From\" email:\t\t"),
		},
		To: EmailStruct{
			Name:  ask("Enter \"To\" name:\t\t"),
			Email: ask("Enter \"To\" email:\t\t"),
		},
		Server:           ask("Enter SMTP server:\t\t"),
		Port:             ask("Port:\t\t\t\t"),
		ScanningInterval: ask("Scan interval:\t\t\t"),
		BlacklistPath:    ask("Path to blacklist file:\t"),
		LogFilesPath:     ask("Path to folder with log files:\t"),
	}
	j, err := json.MarshalIndent(c, "", "\t")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Fprintf(w, "%s", j)
	w.Flush()
	fmt.Printf("Configuration file generated: %s.\n", jsonfile)
	return
}

func ask(s string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(s)
	r, _, _ := reader.ReadLine()
	return string(r)
}

