package main

import (
	"os"
	"regexp"
	"bufio"
	"fmt"
	"time"
	"path/filepath"
	"strings"
)

func analyze(log_name string, offset int64, banned_urls []string, all_banned_urls_found map[string]int) (string, map[string]int, error) {

	defer timeTrack(time.Now(), "~analyze() of file " + filepath.Base(log_name) + "~")

	log_file, err := os.Open(log_name)
	if err != nil {
		return "", nil, err //means that entry from logs_info will be removed if that file doesn't exist
	}
	defer log_file.Close()

	log_file.Seek(offset, 0) //skip lines analyzed in the past


	email, err := regexp.Compile("[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*")
	check(err)
	url, err := regexp.Compile(`(([a-z0-9]+)(\.|\_|\-)?)+\.([a-z]+)`) //regex for url
	check(err)
	ip_addr, err := regexp.Compile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`) //regex for ip addresses
	check(err)
	section_mark, err := regexp.Compile(`----------`) //regex for mark for new smtp session in mdaemon log files.
	check(err)

	scanner := bufio.NewScanner(log_file)
	var banned_report = make(map[string]int)

	found := 0
	var report string

	//MDaemon log format: skip header: 5 lines
	for i := 0; i < 5; i++ {
		scanner.Scan()
	}

	var progress int = 0

	var new_log_file_size int64 = 0
	fi, err := os.Stat(log_name)
	if err == nil {
		// get the size
		new_log_file_size = fi.Size()
	}

	//Every log section ends with mark: ----------

	var ips []string
	var log_entry string

	for scanner.Scan() {

		log_entry = scanner.Text()

		sectionMarkFound := section_mark.MatchString(scanner.Text())
		for sectionMarkFound == false { // continue scan and copy until section mark
		sectionMarkFound = section_mark.MatchString(scanner.Text())
			log_entry += "\n" + scanner.Text() //log entry means 1 section of log/1 event
			if !scanner.Scan() {break} //break cycle if there are nothing more to scan

			progress++
			if progress%1000 == 0 {
				off, _ := log_file.Seek(0, 1)
				fmt.Printf("\r......Scanned: %d lines of log. Size: %d / %d MB......", progress, off/1000000, new_log_file_size/1000000)
			}
		} //todo:!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

		if sectionMarkFound == true {
			//okay, we copied 1 full log entry. Let's find urls and ips in it and compare to blacklist
			sectionMarkFound = false
			urlsAndIps := make([]string, 0)
			for _, strings_found := range ip_addr.FindAllString(log_entry, -1) { //search for ips in log entry
				urlsAndIps = append(urlsAndIps, strings_found)
			}

			for _, strings_found := range email.FindAllString(log_entry, -1) { //search for e-mails in log entry
				urlsAndIps = append(urlsAndIps, strings_found)
			}

			for _, strings_found := range url.FindAllString(log_entry, -1) { //search for urls in log entry
				urlsAndIps = append(urlsAndIps, strings_found)
			}

			for _, found_match := range urlsAndIps { //compare found urls and ips from log file_bs with every url and ip from blacklist.

				for _, banned := range banned_urls {

					if banned != "" {
						if strings.Contains(found_match, banned) {
							found++ //counter for found intersection
							if _, ok := banned_report[banned]; ok { //check if i already found that banned url, count them for summary in report.
								banned_report[banned]++
							} else {
								banned_report[banned] = 1
							}

							report += "\n\n\n..........\nFound banned \"" + banned + "\" in section: \n" + log_entry

							var flag = false
							for _, ip := range ips {
								if ip == banned {
									flag = true
								}
								if flag {
									ip += banned
								}
							}
						}
					}
				}
			}
		}
	} //todo:!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

	if ips != nil {
		for _, ipd := range ips {
			report += fmt.Sprintf(" %s", ipd)
		}
		fmt.Printf(report)
	}

	lines := 0
	var sheet string
	sheet = fmt.Sprintf("\n\n\nLog analyzer REPORT for file: %s \r\nFound %d suspicious events!: ", log_name, found)
	for url, count := range banned_report {
		sheet += fmt.Sprintf("%d times: %s; ", count, url)
		lines++
		if lines == 10 {
			sheet += "\n"
		}
	}

	for url, count := range banned_report {
		if _, ok := all_banned_urls_found[url]; ok { //check if i already found that banned url, count them for summary in report.
			all_banned_urls_found[url] += count
		} else {
			all_banned_urls_found[url] = count
		}
	}

	a := time.Now().String() // why time appears with some trash in the tail?
	clearTime := a[:len(a)-29]
	sheet += fmt.Sprintf("\nTIME: %s", clearTime) + report

	if found > 0 {
		return sheet, all_banned_urls_found, err
	} else {
		return "", all_banned_urls_found, err
	}
}