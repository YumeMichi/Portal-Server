.PHONY:clean install xcapi

PROG = portal-server

xcapi:
	go install ${PROG}

clean:
	rm ./bin -rf
	rm pkg -rf
