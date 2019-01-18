package main

import (
	"net/smtp"
	"log"
	"os"
	"io/ioutil"
	"encoding/json"
	"fmt"
	"path/filepath"
)

func alertMail (subject string, msg string) {
		jsonfile := filepath.Dir(os.Args[0]) + "\\conf.json"

		if _, err := os.Stat(jsonfile); err != nil {
			elog.Info(500, err.Error())
			log.Fatalf("Unable to find configuration file (%s).\n", jsonfile)
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

	var (
		from     = fmt.Sprintf(`"%s" <%s>`, c.From.Name, c.From.Email)
		to       = fmt.Sprintf(`"%s" <%s>`, c.To.Name, c.To.Email)
		server   = c.Server
		port     = c.Port
	)

	//if interval[0] == '+' || interval[0] == '-' {
	//	interval = strings.Replace(interval, string(interval[0]), "", -1)
	//}

	headers := make(map[string]string)
	headers["From"] = from
	headers["To"] = to

	// Connect to the remote SMTP server.
cd, err := smtp.Dial(server+":"+port)
if err != nil {
	elog.Info(500, err.Error())
	log.Fatal(err)
}

// Set the sender and recipient first
if err := cd.Mail(headers["From"]); err != nil {
	elog.Info(500, err.Error())
	log.Fatal(err)
}

if err := cd.Rcpt(headers["To"]); err != nil {
	elog.Info(500, err.Error())
	log.Fatal(err)
	}

// Send the email body.
wc, err := cd.Data()
if err != nil {
	elog.Info(500, err.Error())
	log.Fatal(err)
}


	report := fmt.Sprintf("\n               _                                  _                               _                         	")
	report += fmt.Sprintf("\n              | |                                | |                             | |                        	")
	report += fmt.Sprintf("\n _ __ ___   __| | __ _  ___ _ __ ___   ___  _ __ | | ___   __ _  __ _ _ __   __ _| |_   _ ________ _ __		")
	report += fmt.Sprintf("\n| '_ ` _ \\ / _` |/ _` |/ _ \\ '_ ` _ \\ / _ \\| '_ \\| |/ _ \\ / _` |/ _` | '_ \\ / _` | | | | |_  / _ \\| '__|")
	report += fmt.Sprintf("\n| | | | | | (_| | (_| |  __/ | | | | | (_) | | | | | (_) | (_| | (_| | | | | (_| | | |_| |/ /  __/| |   		")
	report += fmt.Sprintf("\n|_| |_| |_|\\__,_|\\__,_|\\___|_| |_| |_|\\___/|_| |_|_|\\___/ \\__, |\\__,_|_| |_|\\__,_|_|\\__, /___\\___||_| ")
	report += fmt.Sprintf("\n                                                           __/ |                     __/ |                  	")
	report += fmt.Sprintf("\n                                                          |___/                     |___/         		    	")
	report += fmt.Sprintf("\n			    ______ ___________ ___________ _____")
	report += fmt.Sprintf("\n			    | ___ \\  ___| ___ \\  _  | ___ \\_   _|")
	report += fmt.Sprintf("\n			    | |_/ / |__ | |_/ / | | | |_/ / | |")
	report += fmt.Sprintf("\n			    |    /|  __||  __/| | | |    /  | |")
	report += fmt.Sprintf("\n			    | |\\ \\| |___| |   \\ \\_/ / |\\ \\  | |")
	report += fmt.Sprintf("\n			    \\_| \\_\\____/\\_|    \\___/\\_| \\_| \\_/")

	report += msg

_, err = fmt.Fprintf(wc, "From: " + headers["From"] + "\r\n" +
"To: " + headers["To"] + "\r\n" +
"Subject: " + subject + "\r\n" +
"\r\n" + report)

if err != nil {
	elog.Info(500, err.Error())
	log.Fatal(err)
}

err = wc.Close()
if err != nil {
	elog.Info(500, err.Error())
	log.Fatal(err)
}

// Send the QUIT command and close the connection.
err = cd.Quit()
if err != nil {
	elog.Info(500, err.Error())
	log.Fatal(err)
}
}