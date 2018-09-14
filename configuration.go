package main

//Config - a basic structure of configurations
type Config struct {
	From          EmailStruct `json:"from"`
	To            EmailStruct `json:"to"`
	Server        string      `json:"server"`
	Port          string      `json:"port"`
	BlacklistPath string      `json:"blacklistPath"`
	LogFilesPath  string      `json:"logFilesPath"`

	ScanningInterval string `json:"interval"`
}

//EmailStruct - creates a basic email structure
type EmailStruct struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}
