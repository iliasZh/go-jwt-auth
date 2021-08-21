package main

import (
	"log"

	"github.com/spf13/viper"
)

const configFile string = "config.yaml"

func viperInit() {
	viper.SetConfigFile(configFile)
	viper.ReadInConfig()
}

func viperGetString(name string) string {
	if viper.ConfigFileUsed() != configFile {
		log.Fatal("error: config file for Viper not set, use ViperInit() first")
	}
	return viper.GetString(name)
}

func viperGetInt(name string) int {
	if viper.ConfigFileUsed() != configFile {
		log.Fatal("error: config file for Viper not set, use ViperInit() first")
	}
	return viper.GetInt(name)
}
