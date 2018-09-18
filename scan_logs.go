//this file contains two functions: scan_logs() and analyze()
//scan_logs is detecting log files in current directory, reads logs_info file to determine which log file was scanned to what offset,
//then it decides either to scan or not to scan file, and calls analyze()

//analyze() is opening file, compiles regex, uses regex, finds events in log file entries, if found - creates report and e-mails with sendMail(), end.

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
	"log"
	"encoding/json"
	"time"
)

func scan_logs()  {

	var (
		blacklist_changed bool = false
		log_name string
		offset int64
	)

	ex, err := os.Executable()
	chech(err)

	jsonfile := "./conf.json"
	if err != nil {
		panic(err)
	}

	if _, err := os.Stat(jsonfile); err != nil {
		log.Fatalf("Unable to find configuration file [%s].\n", jsonfile)
		log.Fatalf("Error: %s", err.Error())
		return
	}
	data, err := ioutil.ReadFile(jsonfile)
	if err != nil {
		log.Fatalln(err)
	}
	c := &Config{}
	err = json.Unmarshal(data, c)
	if err != nil {
		println(err)
		return
	}

	var (
		blacklistPath = c.BlacklistPath
		logFilesPath  = c.LogFilesPath
	)

	dir := filepath.Dir(ex)
	fmt.Printf("\nworking in directory: "+ dir+"\n")

	fmt.Printf("read hash\n")

	//scan blacklist hash
	root := blacklistPath+"_hash"
	file_blacklist_hash, err := os.Open(root)
	defer file_blacklist_hash.Close()
	chech(err)
	scanner_hash_blacklist := bufio.NewScanner(file_blacklist_hash)
	scanner_hash_blacklist.Scan()
	old_hash_blacklist:=scanner_hash_blacklist.Text()
	root = blacklistPath
	new_hash_blacklist,err := hash_file_md5(root)
	chech(err)
	if old_hash_blacklist != new_hash_blacklist { //check if blacklist has changed
		blacklist_changed = true //if blacklist changed scan all log files from the bottom, ignoring offset value
		offset = 0
		root = 	blacklistPath+"_hash"
	}

	fmt.Printf("read blacklist\n")

	//scan blacklist
	root = blacklistPath
	file_blacklist, _ := os.Open(root)
	defer file_blacklist.Close()
	scanner_blacklist := bufio.NewScanner(file_blacklist)
	banned_urls := make([]string, 0)
	for scanner_blacklist.Scan() {
		banned_urls = append(banned_urls, scanner_blacklist.Text()) //collect all banned urls and ip addresses in one array
	}

	fmt.Printf("read logs_info\n")

	root = "./logs_info.dat"
	logs_info := make([]string, 0)
	dat_file, err := os.Open(root)
	defer dat_file.Close()
	chech(err)
	scanner := bufio.NewScanner(dat_file)

	scanner.Scan() //skip title: 2 lines
	scanner.Scan()

	for scanner.Scan() {
		if scanner.Text() != "" {
			logs_info = append(logs_info, scanner.Text()) //logs_info file contains name of log file, offset (byte where analyze ended last time), file size: [name, offset, size]
		} //collect all info into logs_info string
	}

	file_names := make([]string, 0)

	err = filepath.Walk(logFilesPath + "/", func(path string, info os.FileInfo, err error) error {
		if info.IsDir() && (info.Name() != filepath.Base(logFilesPath)) { //skip all directories excluding root directory
			return filepath.SkipDir
		}
		if filepath.Ext(path) == ".log" {
			file_names = append(file_names, filepath.Base(path)) //collect all .log file names from current directory
		}
		return nil
	})
	chech(err)

	fmt.Printf("find log files\n")
	var names string
	if len(file_names) > 0 {
		for w := range file_names {
			names += file_names[w] + "\n"
		}
	} else {
		//remove logs_info because there no log files in directory
		dat_file.Close()
		err = os.Remove("./logs_info.dat")
		chech(err)
		fmt.Printf(fmt.Sprintf("...buuut no log files found in %s%s", logFilesPath, "/"))
		return
	}

	dat := "###########################################" + "\r\n" + "Name \t\t\t\t Offset" //template for file with updated values

	fmt.Printf("compare files to logs info\n")

	//compare actual log names from working directory to logs_info. If logs_info have non-existing file in directory: delete it. If it's some file in directory,
	//not included in logs info - add it, with 0 offset.

	if len(logs_info) > 0 {
		for f := range file_names {
			var recordFound bool
			for x := range logs_info {
				recordFound = strings.Contains(logs_info[x], file_names[f]) // check if there is record in logs_info.dat of a file from directory
				if recordFound == true {
					break
				}
			}
			if recordFound == false {
				logs_info = append(logs_info, file_names[f]+" 0") //for new files write: filename 0(offset)
			}
		}
	} else {
		logs_info = file_names
		for l := range logs_info {
			logs_info[l] += " 0" //add every file in directory, in case logs_info is empty
		}
		fmt.Printf("missing logs_info. Scan every log file from the beginning\n")
	}

	//println("\n\nlogs_info.dat: \n")
	//for _, info := range file_names {
	//	println(info)
	//}
	//
	//println("\n\nfile_names: \n")
	//for _, name := range file_names {
	//	println(name)
	//}

	//okay, now we have full, truly actual log files list in logs_dat. Let's analyze them:

	for z := range logs_info {
		info := strings.Fields(logs_info[z]) //every line contains: log file name, offset(where ananlyze ended last time with that file)
		log_name = info[0]
		offset, err = strconv.ParseInt(info[1], 10, 64)
		chech(err)

		var new_log_file_size int64
		fi, err := os.Stat(logFilesPath + "/" + log_name)
		if err == nil {
			// get the size
			new_log_file_size = fi.Size()
			chech(err)

			if new_log_file_size > offset {
				logs_info[z] = fmt.Sprintf("%s %d", log_name, new_log_file_size)
				chech(err)
			}

			if blacklist_changed == true {
				offset = 0
			} else {
				offset, err = strconv.ParseInt(info[1], 10, 64)
				chech(err)
			}
		}

		if offset == 0 {
			fmt.Printf("\n%s file never been scanned. Scan from the bottom!", info[0])
		} else if offset == new_log_file_size {
			dat += "\r\n" + logs_info[z]
			fmt.Printf("\n%s file size hasn't been changed! Scan skipped.", info[0])
			continue
		} else if offset < new_log_file_size {
			fmt.Printf("case 3!\n")
			fmt.Printf("\n%s file have been scanned before. Start scan where it's been ended.", info[0])
		}

		fmt.Printf(fmt.Sprintf("\ndecided what to do with file %s. Scan from %d to %d.\n", log_name, offset, new_log_file_size))

		report, found, err := analyze(logFilesPath + "/" + log_name, offset, banned_urls) //analyze current log file

		if os.IsNotExist(err) {
			fmt.Printf(".. aaand it's not found. Error: "+err.Error())
		} else if err == nil {
			rar := fmt.Sprintf("\r\n%s %d", log_name, new_log_file_size)
			dat += rar

			if found > 0 {
				alertMail(fmt.Sprintf("Alert-report for file %s! %d suspicious events!", log_name, found), report)
			}
		}
	}

	root = "./logs_info.dat" //write logs_info
	err = ioutil.WriteFile(root, []byte(dat), 0466)
	chech(err)
	if blacklist_changed {
		root = blacklistPath + "_hash"				 //write blacklist_hash
		err = ioutil.WriteFile(root, []byte(new_hash_blacklist), 0466) // if everything ok, write new hash of blacklist.
		chech(err)
		println("\r\nblacklist hash written successfully:\r\n" + new_hash_blacklist)
	}
}

func analyze(log_name string, offset int64, banned_urls []string) (string, int, error) {

	fmt.Printf("open log file\n")

	log_file, err := os.Open(log_name)
	if err != nil {
		return "", 0, err //means that entry from logs_info will be removed if that file doesn't exist
	}
	defer log_file.Close()

	fmt.Printf("seek to offset\n")

	log_file.Seek(offset, 0) //skip lines analyzed in the past

	fmt.Printf("compile regex\n")

	url, err := regexp.Compile(`(([a-z0-9]+)(\.|\_|\-)?)+\.([a-z]+)`)   //regex for url
	chech(err)
	ip_addr, err := regexp.Compile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`) //regex for ip addresses
	chech(err)

	//section_mark, err := regexp.Compile(`----------`) //regex for section mark in mdaemon log files.
	//chech(err)

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

		//sectionMarkFound := section_mark.MatchString(scanner.Text())
		//for sectionMarkFound == false { // continue scan and copy until section mark
		//sectionMarkFound = section_mark.MatchString(scanner.Text())
		//	log_entry += "\n" + scanner.Text() //log entry means 1 section of log/1 event
		//	if !scanner.Scan() {break} //break cycle if there are nothing more to scan

		progress++
		if progress%1000 == 0 {
			off,_ := log_file.Seek(0, 1)
			fmt.Printf("\r......Scanned: %d lines of log. Size: %d / %d MB......", progress, off/1000000, new_log_file_size/1000000)

		}
		//} todo:!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

		//if sectionMarkFound == true {
		//	//okay, we copied 1 full log entry. Let's find urls and ips in it and compare to blacklist
		//sectionMarkFound = false
		urlsAndIps := make([]string, 0)
		for _, strings_found := range ip_addr.FindAllString(log_entry, -1) { //search for ip's in log entry
			urlsAndIps = append(urlsAndIps, strings_found)
		}

		for _, strings_found := range url.FindAllString(log_entry, -1) { //search for url's in log entry
			urlsAndIps = append(urlsAndIps, strings_found)
		}

		for _, found_match := range urlsAndIps { //compare found urls and ips from log file_bs with every url and ip from blacklist.
			for _, banned := range banned_urls {
				if banned != "" {
					if strings.Contains(found_match, banned) {
						found++ //counter for found intersection
						if _,ok := banned_report[banned]; ok {//check if i already found that banned url, count them for summary in report.
							banned_report[banned]++
						} else { banned_report[banned] = 1 }

						slices:= strings.Fields(log_entry)
						aaa:=strings.Split(slices[0], ".")
						times, err := strconv.ParseInt(aaa[0], 10, 64)
						chech(err)
						slices[0] = time.Unix(times, 0).String()	// Epoch time to normal time

						log_entry=""

						for i := range slices {
							log_entry += slices[i] + " "
						}

						report += "\n\n\n..........\nFound banned \"" + banned + "\" in section: \n" + log_entry

						var flag bool = false
						for _, ip := range ips {
							if ip == banned{
								flag = true
							}
							if flag {
								ip+=banned
							}
						}
					}
				}
			}
		}
	}
	//} todo:!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

	if ips != nil {
		for _,ipd := range ips {
			report+= fmt.Sprintf(" %s", ipd)
		}
		fmt.Printf(report)
	}

	lines:=0
	var sheet string
	sheet = fmt.Sprintf("\n\n\nMdaemon Log analyzer REPORT for file: %s \r\nFound %d suspicious events!: ", log_name, found)
	for url, count := range banned_report {
		sheet += fmt.Sprintf("%d times: %s; ", count, url)
		lines++
		if lines==10 { sheet += "\n" }
	}
	sheet += "\nTIME: " + time.Now().String() + "\n"
	sheet += report

	return sheet, found, err
}

func chech (err error) {
	if err != nil {
		println("\n\n" + err.Error())
	}
}