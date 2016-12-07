package xclog

import (
	"fmt"
	"log"
	"os"
	"time"
)

var (
	Xclog *log.Logger
)

func InitLog() {
	logPath := `/tmp/portal-server_` + time.Now().Format("20060102150405") + `.log`

	fp, err := os.Create(logPath)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	Xclog = log.New(fp, "[portal-server]", log.Ldate|log.Ltime|log.Lshortfile)

	Xclog.Println("init xclog complete.")
}
