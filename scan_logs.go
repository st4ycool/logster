//this file contains two functions: scan_logs() and analyze()
//scan_logs is detecting log files in current directory, reads logs_info file to determine which log file was scanned to what offset,
//after it decides either to scan or not to scan file, and calls analyze()

//analyze() applies regex to log entries to find something from blacklist. If found - creates report and e-mails with sendMail()

package main

import (
	"bufio"
	"strings"
	"fmt"
	"os"
	"strconv"
	"io/ioutil"
	"path/filepath"
	"log"
	"encoding/json"
	"time"
	"regexp"
)

func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("\nfunction %s took %s\n", name, elapsed)
}

func scan_logs() {

	var (
		log_name          string
		offset            int64
	)

	//Read configuration file (e-mail credentials, scanning interval, paths to log_files, etc)
	jsonfile := filepath.Dir(os.Args[0]) + "\\conf.json"
	if _, err := os.Stat(jsonfile); err != nil {
		elog.Info(500, err.Error())
		log.Fatalf("\nUnable to find configuration file [%s]", jsonfile)
		return
	}

	data, err := ioutil.ReadFile(jsonfile)

	if err != nil {
		elog.Info(2, err.Error())
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

	//Read logs_info.dat file that contains name and offset for each file, and for extra one for blacklist
	dat_f := filepath.Dir(os.Args[0]) + "\\logs_info.dat"

	if _, err := os.Stat(dat_f); err != nil {
		fmt.Printf("\nUnable to find logs_info file [%s]. ", dat_f)
		os.Create(dat_f)
	}

	dat_file, err := os.Open(dat_f)

	defer dat_file.Close()
	check(err)
	logs_info_scanner := bufio.NewScanner(dat_file)

	logs_info_scanner.Scan() //skip blacklist title: 2 lines
	logs_info_scanner.Scan()

	var blacklist_offset int64
	if logs_info_scanner.Scan() {
		blacklist_offset, err = strconv.ParseInt(logs_info_scanner.Text(), 10, 64)
		check(err)
	}

	logs_info_scanner.Scan() //skip log files title: 2 lines
	logs_info_scanner.Scan()

	logs_info := make([]string, 0)
	for logs_info_scanner.Scan() {
		if logs_info_scanner.Text() != "" {
			logs_info = append(logs_info, logs_info_scanner.Text())
		}
	}

	//Scan blacklist file (blacklist file should contain one forbidden url/domain [according to regex] in each line of file)
	var blacklist_size int64
	fi, err := os.Stat(blacklistPath)
	if err == nil {
		// get the size
		blacklist_size = fi.Size()
		check(err)
	} else {
		elog.Info(500, fmt.Sprintf("Can't open %s! Error: %v", blacklistPath, err))
		log.Fatalf("can't open blacklist file! %v", err)
	}

	file_blacklist, _ := os.Open(blacklistPath)
	defer file_blacklist.Close()
	scanner_blacklist := bufio.NewScanner(file_blacklist)
	use_only_new_blacklist_items := false

	//Decide to scan logs with recently added blacklist urls OR continue scanning upcoming log lines for each blacklist url
	if blacklist_size > blacklist_offset {	//if blacklist size changed == something added, so scan log from beginning only for recently added urls
		fmt.Printf("\nBlacklist has grown.")
		file_blacklist.Seek(blacklist_offset, 0)
		use_only_new_blacklist_items = true
	}

	banned_urls := make([]string, 0) //store all blacklist items (urls or ips, or domain names)
	for scanner_blacklist.Scan() {
		a:=scanner_blacklist.Text()
		if  a != "" {
			banned_urls = append(banned_urls, scanner_blacklist.Text())
		}
	}

	//Find all .log files in path set in conf.json
	log_file_names := make([]string, 0)

	err = filepath.Walk(logFilesPath + "\\", func(path string, info os.FileInfo, err error) error {	//recursive walk through directory
		if info.IsDir() && (info.Name() != filepath.Base(logFilesPath)) { //skip all directories excluding root directory
			return filepath.SkipDir
		}
		mdaemonLogFileRegexp, err := regexp.Compile(`MDaemon-20\d\d-\d\d-\d\d-SMTP-\(in\).log`) //regex for url
		check(err)
		//if filepath.Ext(path) == ".log" {
		if mdaemonLogFileRegexp.MatchString(info.Name()) {
			log_file_names = append(log_file_names, filepath.Base(path)) //collect all .log file names from current directory
		}
		return nil
	})
	check(err)


	//If there is no .log file: remove logs_info.dat
	if len(log_file_names) < 1 {
		dat_file.Close()
		err = os.Remove(filepath.Dir(os.Args[0]) + "\\logs_info.dat")
		check(err)
		fmt.Printf(fmt.Sprintf("\n...buuut no log files found in %s%s", logFilesPath, "/"))
		return
	}

	dat := 	"###########################################" + //"dat" is new logs_info.dat file, that will be written in the end
			"\nblacklist offset:\n" +
	   		 fmt.Sprintf("%d", blacklist_size) + "\n" +
			"###########################################" +
			"\nlog files offset:"

	//Look if there are record in logs_info for found files If logs_info have non-existing file in directory: delete it. If it's some file in directory,
	//not included in logs info - add it, with 0 offset.

	if len(logs_info) > 0 {
		for f := range log_file_names {	//todo: isn't range for slices return 2 index and value? Can't understand how this works
			var recordFound bool
			for x := range logs_info {
				recordFound = strings.Contains(logs_info[x], log_file_names[f]) // check if there is record in logs_info.dat of a file from directory
				if recordFound == true {
					break		//if matches means file exist, so break (go to next record)
				}
			}
			if recordFound == false {	//if not matches means there are no record in logs_info, but file exist. So, add record it into logs_info
				logs_info = append(logs_info, log_file_names[f]+" 0") //new files comes with 0 offset, what means they wasnt scanned before
			}
		}
	} else { //if logs_info is empty, just add records for every found file from directory
		logs_info = log_file_names
		for l := range logs_info {
			logs_info[l] += " 0"
		}
		fmt.Printf("\nmissing logs_info. Scan every log file from the beginning")
	}



	var full_report string
	var all_banned_urls_found = make(map[string]int)

	//Okay, now we have full, actual log files list in logs_dat. Let's analyze them:
	for z := range logs_info {
		info := strings.Fields(logs_info[z]) //every line contains: log file name, offset(where analyze ended last time with that file)
		log_name = info[0]
		offset, err = strconv.ParseInt(info[1], 10, 64)
		check(err)

		//Check if log file has grown
		var new_log_file_size int64
		fi, err := os.Stat(logFilesPath + "\\" + log_name)
		if err == nil {
			new_log_file_size = fi.Size()
			check(err)
			if new_log_file_size > offset {
				logs_info[z] = fmt.Sprintf("%s %d", log_name, new_log_file_size)
				check(err)
			}
			offset, err = strconv.ParseInt(info[1], 10, 64)
			check(err)
		}


		//Decide how to scan log file, according to its current size
		if offset == 0 {
			fmt.Printf("\n%s file never been scanned. Scan from the bottom!", info[0])
		} else if offset == new_log_file_size && !use_only_new_blacklist_items {
			dat += "\r\n" + logs_info[z]
			fmt.Printf("\n%s file size hasn't been changed! Scan skipped.", info[0])
			continue
		} else if offset < new_log_file_size {
			fmt.Printf("\n%s file have been scanned before. Start scan where it's been ended.", info[0])
		}

		if use_only_new_blacklist_items {
			offset = 0 	//if it's something added in blacklist, compare only them and scan all logs from 0
			fmt.Printf(fmt.Sprintf("\nScan %s logfile from 0", log_name))
			} else {
				fmt.Printf(fmt.Sprintf("\ndecided what to do with file %s. Scan from %d to %d.", log_name, offset, new_log_file_size))
		}

		//Analyze current log file
		var report string
		report, all_banned_urls_found, err = analyze(logFilesPath + "\\" + log_name, offset, banned_urls, all_banned_urls_found)

		//if file exist and scan completed
		if err == nil { //if something found
			rar := fmt.Sprintf("\r\n%s %d", log_name, new_log_file_size)
			dat += rar
			if len(report) > 0 {
				full_report+=report
			}
		} else if os.IsNotExist(err) {	 //if file not found
			fmt.Printf(".. aaand it's not found. Error: " + err.Error())
		} else {
			fmt.Printf("...Sorry. Something went wrong: " + err.Error())
		}
	}

	//if something found: report it via e-mail
	if len(full_report) > 0 {

		var found_at_all int
		for _, count := range all_banned_urls_found {
			found_at_all+=count
		}

		lines := 0
		var sheet string
		sheet = fmt.Sprintf("\n\n\n\r\nFound %d events!: ", found_at_all)
		for url, count := range all_banned_urls_found {
			sheet += fmt.Sprintf("%d times: %s; ", count, url)
			lines++
			if lines == 10 {
				sheet += "\n"
			}
		}
		sheet+="\n\n------------------------------------------------------------------------------------------------------"
		sheet+="\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
		sheet+="\n------------------------------------------------------------------------------------------------------\n\n\n\n\n\n"

		a := time.Now().String() // why time appears with some trash in the tail?
		clearTime := a[:len(a)-29]
		sheet += fmt.Sprintf("\nTIME: %s", clearTime) + full_report

		filename := filepath.Dir(os.Args[0]) + "\\loganalyzer-report.txt"
		err = ioutil.WriteFile( filename, []byte(sheet), 0466)
		check(err)

		alertMail(fmt.Sprintf("MDaemon log Alert-report! %d suspicious events found!", found_at_all), sheet)
	}

	//write logs_info
	err = ioutil.WriteFile(filepath.Dir(os.Args[0]) + "\\logs_info.dat", []byte(dat), 0466)
	check(err)
	}


