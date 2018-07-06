package main

import (
	"bufio"
	"strings"
	"fmt"
	"regexp"
	"os"
	"strconv"
	"io/ioutil"
	"path/filepath"
)

func scan_logs()  {

	var (
		blacklist_changed bool = false
		log_name string
		offset int64
		old_log_file_size int64
		)

	//scan blacklist hash
	file_blacklist_hash, _ := os.Open("blacklist_hash.dat")
	defer file_blacklist_hash.Close()
	scanner_hash_blacklist := bufio.NewScanner(file_blacklist_hash)
	scanner_hash_blacklist.Scan()
	old_hash_blacklist:=scanner_hash_blacklist.Text()
	new_hash_blacklist,_ := hash_file_md5("blacklist.txt")
	if old_hash_blacklist != new_hash_blacklist { //check if blacklist has changed
		blacklist_changed = true // if blacklist changed I gonna scan all log files from the bottom, ignoring offset value
		offset = 0
		ioutil.WriteFile("blacklist_hash.dat", []byte(new_hash_blacklist), 0466)
	}

	elog.Info(1, "read hash")


	//scan blacklist
	file_blacklist, _ := os.Open("blacklist.txt")
	defer file_blacklist.Close()
	scanner_blacklist := bufio.NewScanner(file_blacklist)
	banned_urls := make([]string, 0)
	for scanner_blacklist.Scan() {
		banned_urls = append(banned_urls, scanner_blacklist.Text()) //collect all banned urls and ip addresses in one array
	}

	elog.Info(1, "read blacklist")

	dat_file, _ := os.Open("logs_info.dat")
	defer dat_file.Close()

	logs_info := make([]string, 0)
	scanner := bufio.NewScanner(dat_file)

	scanner.Scan() //skip 2 first lines. There are infos
	scanner.Scan()

	for scanner.Scan() {
		if scanner.Text() != "" {
			logs_info = append(logs_info, scanner.Text())			//logs_info file contains name of log file, offset (byte where analyze ended last time), file size: [name, offset, size]
		}															//collect all info into logs_info string slice
	}

	var files []string
	file_names := make([]string, 0)
	root, e := os.Getwd()
	if e != nil {
		panic(e)
	}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".log" {
			log_file, _ := os.Open(path)
			defer log_file.Close()
			files = append(files, path)
			file_names = append(file_names, info.Name()) //collect all .txt file names from current directory
		}
			return nil
	})
	if err != nil {
		panic(err)
	}

	elog.Info(1, "got file names")

	dat := "###########################################" + "\r\n" + "Name Offset Size"+ "\r\n" //template for file with updated values

	if len(logs_info) > 0 {
		for f:= range file_names {
			var recordFound bool
			for x := range logs_info {
				recordFound = strings.Contains(logs_info[x], file_names[f]) // check if there a record of file in directory in log info file
				if recordFound==true {break}
			}
			if recordFound == false {
				logs_info = append(logs_info, file_names[f]+" 0 0")
			}
		}
	} else {
		logs_info=file_names
		for l:= range logs_info {
			logs_info[l]+=" 0 0"
		}
	}

	elog.Info(1, "updated logs_info")

		for z:= range logs_info {

			info := strings.Fields(logs_info[z])                     //every line contains: log file name, offset(where ananlyze ended last time with that file), file size(to check if file has changed)
			log_name = info[0]
			if blacklist_changed == true {
				offset = 0
				} else {
					offset, _ = strconv.ParseInt(info[1], 10, 64)}
			old_log_file_size, _ = strconv.ParseInt(info[2], 10, 64)
			new_log_file_size, _ := getFileSize(log_name)

			switch {
			case old_log_file_size == 0 && offset == 0: if blacklist_changed!=true {println("\n" + log_name + " file record not found. Scan from the bottom! ")}
			case old_log_file_size == new_log_file_size: dat +="\r\n" +  logs_info[z]
														 if blacklist_changed!=true {println(info[0] + " file size hasn't been changed! Scan skipped. ")}
														 continue
			case old_log_file_size != new_log_file_size: if blacklist_changed!=true {println(info[0] + " file record found. Starting scan where it's been ended.")}

			}


			dat += "\r\n" + log_name + " " + strconv.FormatInt(new_log_file_size, 10) + " " + strconv.FormatInt(new_log_file_size, 10)

			sheet, found := analyze(log_name, offset, banned_urls) //analyze current log file
			report := "#############" + "\r\n" + "Mail-log analyzer REPORT for file: " + log_name + "\r\n" + "Found " + string(found) + " e-mails from blacklist!" + "\r\n" + "#############" + "\r\n" + "\r\n"
			report += sheet
			if found > 0 {
				alertMail("u.anikin@morskoybank.com", "u.anikin@morskoybank.com", fmt.Sprintf("Alert-report for file %s! %d blacklist e-mails reveived!", log_name, found), report)
			}
	}
	ioutil.WriteFile("logs_info.dat", []byte(dat), 0466)
	elog.Info(1, "wrote new logs_info.dat")
	println("info written successfully:\r\n"+ dat)
}

func getFileSize (filePath string) (int64, error) {
	fi, e := os.Stat(filePath);
	if e != nil {
		return 0, e
	}
	// get the size
	return fi.Size(), nil
}

func analyze(log_name string, offset int64, banned_urls []string) (string, int) {

	log_file, _ := os.Open(log_name)
	defer log_file.Close()

	log_file.Seek(offset, 0) //skip lines analyzed in the past

	url, _ := regexp.Compile(`(([a-z0-9]+)(\.|\_|\/|\-)?)+\.([a-z]+)`)   //regex for url
	ip_addr, _ := regexp.Compile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`) //regex for ip addresses
	section_mark, _ := regexp.Compile(`----------`)                      //regex for section mark in mdaemon log files.

	scanner := bufio.NewScanner(log_file)

	found := 0
	var report string

	//MDaemon log format: skip header: 5 lines
	for i := 0; i < 5; i++ {
		scanner.Scan()
		//av := scanner.Text()
		//println(av)
	}

	var count int


	//Every log section ends with mark: ----------
	for scanner.Scan() {
		var log_entry string

		sectionMarkFound := section_mark.MatchString(scanner.Text())

		for sectionMarkFound == false { // continue scan and copy until section mark
			sectionMarkFound = section_mark.MatchString(scanner.Text())
			log_entry += "\n" + scanner.Text() //log entry means 1 section of log/1 event
			scanner.Scan()
		}
		if sectionMarkFound == true {	//okay, we copied 1 full log entry. Let's find urls and ips in it and compare to blacklist
			sectionMarkFound = false
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
						report += "\n\n\n\n" + "Found banned : "+ banned + " in next section! \n" + log_entry
					}
				}
			}
		}
		}
	}

	report += fmt.Sprintf("### %d blacklist e-mails found in %s\n", found, log_name)
	//fmt.Printf(report)

	return report, found
}