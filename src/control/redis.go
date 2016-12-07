package control

import (
	"config"
	// "fmt"
	"github.com/garyburd/redigo/redis"
	"xclog"
)

// 重写生成连接池方法
func newPool() *redis.Pool {
	return &redis.Pool{
		MaxIdle: 2000,
		Dial: func() (redis.Conn, error) {
			op := redis.DialDatabase(config.Conf.Redis_db)
			if config.Conf.Redis_pass == "" {
				c, err := redis.Dial("tcp", config.Conf.Redis_host+":"+config.Conf.Redis_port, op)
				if err != nil {
					xclog.Xclog.Println(err.Error())
				}
				return c, err
			} else {
				pass := redis.DialPassword(config.Conf.Redis_pass)
				c, err := redis.Dial("tcp", config.Conf.Redis_host+":"+config.Conf.Redis_port, op, pass)
				if err != nil {
					xclog.Xclog.Println(err.Error())
				}
				return c, err
			}
		},
	}
}