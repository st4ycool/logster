package main

//Config - a basic structure of configurations
type Config struct {
	From          EmailStruct `json:"from"`
	To            EmailStruct `json:"to"`
	Server        string      `json:"server"`
	Port          string      `json:"port"`
	BlacklistPath string      `json:"blacklistPath"`
	LogFilesPath  string      `json:"logFilesPath"`
	Auth		  Auth		  `json:"auth"`

	ScanningInterval string `json:"interval"`
}

type Auth struct {
	Login string `json:"login"`
	Password string `json:"password"`
}

//EmailStruct - creates a basic email structure
type EmailStruct struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}
