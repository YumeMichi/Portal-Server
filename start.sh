#!/bin/sh
echo "start portal-server"
pnum=`ps -ef | grep portal-server | grep -v grep | grep -v _hl| wc -l`
echo pnum
if [ $pnum -gt 0 ]; then

	echo "正在停止已有进程"
	killall portal-server

	sleep 1
	echo "开始启动"
else
	echo "开始启动"
fi
./bin/portal-server&
echo "start portal-server ok"
