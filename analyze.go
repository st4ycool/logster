package main

import (
	"bufio"
	"strings"
	"fmt"
	"regexp"
	"os"
	"strconv"
	"io/ioutil"
)

func analyze() {

	file_specs, _ := os.Open("conf.cfg") //where to start reading log file_bs
	defer file_specs.Close()

	confScanner := bufio.NewScanner(file_specs)
	var offset int64
	var old_hash_blacklist string
	var old_log_file_size int64

	for i:=0;i<3;i++{
		confScanner.Scan()

		switch i {
		case 0: 	x, _ := strconv.Atoi(confScanner.Text())
		         	offset = int64(x)
		case 1: 	old_hash_blacklist = confScanner.Text()
		case 2:		y, _ := strconv.Atoi(confScanner.Text())
		           old_log_file_size = int64(y)
		}
	}

	new_log_file_size, _ := getFileSize("mdaemon.log")

	if old_log_file_size == new_log_file_size {
		return
	}


	new_hash_blacklist, _ := hash_file_md5("blacklist.txt")

	if old_hash_blacklist != new_hash_blacklist {
		offset = 0
	}

	file_bs, _ := os.Open("blacklist.txt")
	defer file_bs.Close()

	scanner := bufio.NewScanner(file_bs)
	banned_urls := make([]string, 0)
	for scanner.Scan() {
		banned_urls = append(banned_urls, scanner.Text()) //collect all banned urls and ip addresses in one array
	}

	//okay, if offset is 0 = means the log file_bs is new. If offset is n-number means we already analyzed log until n-byte
	file_log, _ := os.Open("mdaemon.log")
	defer file_log.Close()

	file_log.Seek(offset, 0) //skip offset lines (with a view not to analyze all log file_bs everytime, but only the new part)

	url, _ := regexp.Compile(`(([a-z0-9]+)(\.|\_|\/|\-)?)+\.([a-z]+)`)
	ip_addr, _ := regexp.Compile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	section_mark, _ := regexp.Compile(`----------`)

	scanner = bufio.NewScanner(file_log)

	found := 0
	var report string

	//MDaemon log format: skip header: 5 lines
	for i := 0; i < 5; i++ {
		scanner.Scan()
		av:=scanner.Text()
		println(av)
	}

	full_section:=true
	var count int
	//Every log entry enclosed with ----------
	//Look for: ---------- at first.
	for scanner.Scan() { //scan to first log entry
		if section_mark.MatchString(scanner.Text()) { //if section mark found
			log_entry := scanner.Text() //log entry means 1 section of log. 1 event
			full_section = false     //full section I mean we scanned both opening(full = false) and closing (full = true) marks
			for full_section == false {
				scanner.Scan()
				log_entry += "\n" + scanner.Text()
				if section_mark.MatchString(scanner.Text()) {
					full_section = true //okay, we copied 1 full log entry. Let's find urls and ips in it and compare to blacklist
				}
			}
			urlsAndIps := make([]string, 0)
			for _, strings_found := range ip_addr.FindAllString(log_entry, -1) { //search for ip's in log entry
				urlsAndIps = append(urlsAndIps, strings_found)
			}

			for _, strings_found := range url.FindAllString(log_entry, -1) { //search for url's in log entry
				urlsAndIps = append(urlsAndIps, strings_found)
			}

			for _, found_match := range urlsAndIps { //compare founded urls and ips from log file_bs with every url and ip from blacklist.
				for _, banned := range banned_urls {
					if banned != "" {
						count++
						if strings.Contains(found_match, banned) {
							found++ //counter for found intersection
							report += log_entry+"\n\n\n"
						}
					}
				}
			}
		}
	}

	report += fmt.Sprintf(" \n\n\n### %d log intersection with blacklist found!\n\ntotal analyzed ip^urls:%d", found, count)
	fmt.Printf(report)

	if found>0 {
		alertMail("u.anikin@morskoybank.com", "u.anikin@morskoybank.com", fmt.Sprintf("Alert-report! %d blacklist e-mails reveived!", found), report)
	}

	fmt.Printf("\nбыло %d", offset)
	offset, _ = file_log.Seek(0, 2)
	fmt.Printf("\nстало %d", offset)

	s := strconv.FormatInt(offset, 10)
	s+="\r\n"+new_hash_blacklist+"\r\n"
	s+= strconv.FormatInt(new_log_file_size, 10)

	ioutil.WriteFile("conf.cfg", []byte(s), 0466)

}

func getFileSize (filePath string) (int64, error) {
	fi, e := os.Stat(filePath);
	if e != nil {
		return 0, e
	}
	// get the size
	return fi.Size(), nil
}