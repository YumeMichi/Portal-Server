package config

import (
	"encoding/json"
	"io/ioutil"
)

type ConfStruct struct {
	Redis_host 	string `json:"redis_host"`
	Redis_port	string `json:"redis_port"`
	Redis_pass 	string `json:"redis_pass"`
	Redis_db   	int    `json:"redis_db"`
	Api_port   	string `json:"api_port"`
	Udp_port   	string `json:"udp_port"`
	Ac_port    	string `json:"ac_port"`
	SharedSecret    string `json:"sharedSecret"`
	Portal_key    	string `json:"portal_key"`
	User_name    	string `json:"user_name"`
	User_pwd    	string `json:"user_pwd"`
}

var (
	Conf ConfStruct
)

func InitConfig() error {
	buf, err := ioutil.ReadFile("./portal-server.conf")
	if err != nil {
		return err
	}
	if err := json.Unmarshal(buf, &Conf); err != nil {
		return err
	}
	return nil
}
