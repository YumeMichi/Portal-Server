package main

import (
	"config"
	"control"
	"fmt"
	"github.com/kataras/iris"
	"xclog"
)

func main() {

	xclog.InitLog() //初始化log模块
	if err := config.InitConfig(); err != nil {
		xclog.Xclog.Println(err.Error())
	}

	control.InitRedispool() //初始化redis连接池

	fmt.Printf("Redis_host:   [%s]\n", config.Conf.Redis_host)
	fmt.Printf("Redis_port:   [%s]\n", config.Conf.Redis_port)
	fmt.Printf("Redis_pass:   [%s]\n", config.Conf.Redis_pass)
	fmt.Printf("Redis_db:     [%d]\n", config.Conf.Redis_db)
	fmt.Printf("Api_port:     [%s]\n", config.Conf.Api_port)
	fmt.Printf("Udp_port:     [%s]\n", config.Conf.Udp_port)
	fmt.Printf("AC_port:      [%s]\n", config.Conf.Ac_port)
	fmt.Printf("SharedSecret: [%s]\n", config.Conf.SharedSecret)
	fmt.Printf("Portal_key:   [%s]\n", config.Conf.Portal_key)
	fmt.Printf("User_name:    [%s]\n", config.Conf.User_name)
	fmt.Printf("User_pwd:     [%s]\n", config.Conf.User_pwd)

	go control.OverTime()	//轮循查看redis中，过期用户踢下线

	api := iris.New()

	//和portal_url的交互
	api.Get("api/portal-server/login", control.Login)
	api.Get("api/portal-server/logout", control.Logout)

	api.Listen(":" + config.Conf.Api_port)

}
