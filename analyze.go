package main

import (
	"bufio"
	"strings"
	"fmt"
	"regexp"
	"os"
)

func analyze() {

	file, _ := os.Open("C:/Users/u.anikin/go/src/windows_daemon/blacklist.txt")
	defer file.Close()

	banned_urls := make([]string, 0)

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		banned_urls = append(banned_urls, scanner.Text()) //collect all banned urls and ip addresses in one array
	}


	file, _ = os.Open("C:/Users/u.anikin/go/src/windows_daemon/mdaemon.log")
	defer file.Close()

	url, _ := regexp.Compile(`(([a-z0-9]+)(\.|\_|\/|\-)?)+\.([a-z]+)`)
	ip_addr, _ := regexp.Compile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

	scanner = bufio.NewScanner(file)

	found := 0
	var report string

	for scanner.Scan() { //look for ip addr or url in every line of log file
		matches := make([]string, 0)

		for _, strings_found := range ip_addr.FindAllString(scanner.Text(), -1) {
			matches = append(matches, strings_found)
		}

		for _, strings_found := range url.FindAllString(scanner.Text(), -1) {
			matches = append(matches, strings_found)
		}

		for _, found_match := range matches {

			for _, banned := range banned_urls { //compare every banned url and ip to line(ip and url) from log file
				if banned != "" {
					if strings.Contains(found_match, banned) {
						report += fmt.Sprintf(" %s\n ---> contains %s\n\n", scanner.Text(), banned)
						//fmt.Printf(" %s\n ---> contains %s\n\n", scanner.Text(), banned)
						found++
					}
				}
			}
		}
	}

	//fmt.Printf(" <###> Totally: %d blacklist intersection with blacklist reported!", found)
	report += fmt.Sprintf(" <###> Totally: %d blacklist intersection with blacklist reported!", found)

	alertMail("u.anikin@morskoybank.com", "u.anikin@morskoybank.com", fmt.Sprintf("MDaemon log alert report: %d blacklist connections found!", found), report)
}