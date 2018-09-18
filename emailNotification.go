package main

import (
	"fmt"
	"os"
	"log"
	"io/ioutil"
	"encoding/json"
	"github.com/gomail-master"
	"crypto/tls"
)

func alertMail (subject string, msg string) {
		jsonfile := "./conf.json"

		if _, err := os.Stat(jsonfile); err != nil {
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

	d := gomail.NewDialer(c.Server, 25, c.From.Email, c.Auth.Password)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	m := gomail.NewMessage()
	m.SetHeader("From", c.From.Email)
	m.SetHeader("To", c.To.Email)
	m.SetAddressHeader("Cc", c.From.Email, c.From.Name)
	m.SetHeader("Subject", subject)
	m.SetBody("", report)
	//m.Attach("/home/Alex/lolcat.jpg")

	// Send the email
	if err := d.DialAndSend(m); err != nil {
		panic(err)
	}

}

