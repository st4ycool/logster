package main

import (
	"net/smtp"
	"log"
	"fmt"
)

func alertMail (from string, to string, subject string, msg string){

// Connect to the remote SMTP server.
c, err := smtp.Dial("mail.lan:25")
if err != nil {
log.Fatal(err)
}

// Set the sender and recipient first
if err := c.Mail(from); err != nil {
log.Fatal(err)
}

if err := c.Rcpt(to); err != nil {
log.Fatal(err)
}

// Send the email body.
wc, err := c.Data()
if err != nil {
log.Fatal(err)
}

_, err = fmt.Fprintf(wc, "From: " + from + "\r\n" +
"To: " + to + "\r\n" +
"Subject: " + subject + "\r\n" +
"\r\n" +
msg)

if err != nil {
log.Fatal(err)
}

err = wc.Close()
if err != nil {
log.Fatal(err)
}

// Send the QUIT command and close the connection.
err = c.Quit()
if err != nil {
log.Fatal(err)
}
}