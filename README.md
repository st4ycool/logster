# logster
Compares squid log with blacklist and reports via e-mail.

***ABOUT:***
Okay. So, logster is just a log parser, that compares requests(urls) from log file to blacklist and e-mails any warnings.

`Example of use`: imagine some gov department reveals information about c&c servers of some botnet or hacker attack. 
You simply add these c&c ip addresses to blacklist, run logster and it will check any *.log file and e-mail you 
if somebody was requesting something from that ip.

***BEFORE START:***
1. Create "conf.json" containing:  
{  
	"from": {  
		"name": "**your name**",  
		"email": "**your e-mail**"  
	},  
	"to": {  
		"name": "**name of recepient 1**",  
		"email": "**e-mail of recepient 1**"  
	},  
	"to": {  
		"name": "**name of recepient 2**",  
		"email": "**e-mail of recepient 2**"  
	},  
	"server": "**your mail server host**",  
	"port": "**port**",  
	"auth": {  
		"login": "**your login**",  
		"password": "**your password**"  
	},  
	"blacklistPath": "**path to file that contains blocked urls or domains or just words: 1 url per line, each line ends with CR LF**",  
	"logFilesPath": "**path to folder where .log files stored**",  
	"interval": "**log files scanning interval**"  
}  
2. Put conf.json file in project folder or near executive.  

***USAGE:*** you can build and run this branch in windows, also executive can be loaded into windows services using cmd:
`logster.exe install` or just run using `logster.exe debug`
all available comands see using command help.

Scan period can be set in conf.json file (edit "interval" field)


