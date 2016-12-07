package control

import (
	"encoding/hex"
	"fmt"
	"github.com/garyburd/redigo/redis"
	"github.com/kataras/iris"
	"net"
	"strconv"
	"strings"
	"xclog"
	"math/rand"
	"time"
	"crypto/md5"
	"config"
)

var (
	redisPool *redis.Pool
)

func InitRedispool() {
	redisPool = newPool()
}

func SendResponse(ctx *iris.Context, errCode, mesg string) {
	respMap := make(map[string]interface{})
	respMap["error_code"] = errCode
	respMap["message"] = mesg
	if err := ctx.JSON(iris.StatusOK, respMap); err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Printf("Send Response OK. resp:[%s]\n\n", respMap)
	}
}

func Login(ctx *iris.Context) {
	fmt.Println("*****************************")
	url_id := ctx.FormValueString("url_id")
	wlanssid := ctx.FormValueString("wlanssid")
	wlanuserip := ctx.FormValueString("wlanuserip")
	wlanusermac := ctx.FormValueString("wlanusermac")
	wlanmac := ctx.FormValueString("wlanmac")
	redirect := ctx.FormValueString("redirect")
	wlanacip := ctx.FormValueString("wlanacip")
	wlanacname := ctx.FormValueString("wlanacname")
	expired := ctx.FormValueString("expired")
	//pgv_pvi := ctx.FormValueString("pgv_pvi")
	//PHPSESSID := ctx.FormValueString("PHPSESSID")
	//callbackparam := ctx.FormValueString("callbackparam")
	//action := ctx.FormValueString("action")
	//timestamp := ctx.FormValueString("_")
	fmt.Printf("url_id = %s\nwlanssid = %s\nwlanuserip = %s\nwlanusermac = %s\nwlanmac = %s\nredirect = %s\nwlanacip = %s\nwlanacname = %s\nexpired = %s\n", url_id, wlanssid, wlanuserip, wlanusermac, wlanmac, redirect, wlanacip, wlanacname, expired)
	fmt.Println("*****************************")

	//生成reqChallenge
	buff := make([]byte, 16)
	attrs := make([]byte, 0)
	reqID := make([]byte, 2)
	userIP := ipToBytes(wlanuserip)
	basIP := ipToBytes(wlanacip)
	serialNo := mkSerialNo(256)
	fmt.Println("serialNo:", serialNo)
	fmt.Println("userIp:", userIP)
	fmt.Println("basIP:", basIP)

	reqChallenge := make([]byte, 32)
	reqChallenge[0] = 2
	reqChallenge[1] = 1
	reqChallenge[2] = 0
	reqChallenge[3] = 0
	reqChallenge[4] = serialNo[0]
	reqChallenge[5] = serialNo[1]
	reqChallenge[6] = 0
	reqChallenge[7] = 0
	reqChallenge[8] = userIP[0]
	reqChallenge[9] = userIP[1]
	reqChallenge[10] = userIP[2]
	reqChallenge[11] = userIP[3]
	reqChallenge[12] = 0
	reqChallenge[13] = 0
	reqChallenge[14] = 0
	reqChallenge[15] = 0
	for i:=0; i<16; i++ {
		buff[i] = reqChallenge[i]
	}

	authen := mkAuthen(buff, attrs, config.Conf.Portal_key)
	fmt.Println("authen:", authen)

	for i:=0; i<16; i++ {
		reqChallenge[16+i] = authen[i]
	}

	//udp协议，建立和AC的udp连接，并且发送challenge
	socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.IPv4(192, 168, 199, 1),
		Port: 2000,
	})
	if err != nil {
		fmt.Println("连接失败!", err)
		xclog.Xclog.Println(err.Error())
		return
	}
	defer socket.Close()

	_, err = socket.Write(reqChallenge)
	if err != nil {
		fmt.Println("发送数据失败!", err)
		xclog.Xclog.Println(err.Error())
		return
	}
	fmt.Println("Send reqChallenge:", reqChallenge)

	socket.SetReadDeadline(time.Now().Add(2 * time.Second))

	// 接收数据, 并判断请求challenge是否成功
	askChallenge := make([]byte, 50)
	_, _, err = socket.ReadFromUDP(askChallenge)
	if err != nil {
		fmt.Println("读取数据失败!", err)
		return
	}
	//fmt.Println("n:", n, " remoteAddr:", remoteAddr)
	fmt.Println("askChallenge:", askChallenge)

	if ((askChallenge[14] & 0xFF) == 0) {
		fmt.Println("发送Challenge请求成功,准备发送reqAuths")
	}
	if ((askChallenge[14] & 0xFF) == 1) {
		fmt.Println("发送Challenge请求被拒绝")
		errLogOut(serialNo, reqID, userIP, basIP, socket)
		return
	}
	if ((askChallenge[14] & 0xFF) == 2) {
		fmt.Println("发送Challenge连接已建立")
	}
	if ((askChallenge[14] & 0xFF) == 3) {
		fmt.Println("系统繁忙，请稍后再试")
		errLogOut(serialNo, reqID, userIP, basIP, socket)
		return
	}
	if ((askChallenge[14] & 0xFF) == 4) {
		fmt.Println("发送Challenge请求出现未知错误")
		errLogOut(serialNo, reqID, userIP, basIP, socket)
		return
	}

	reqID[0] = askChallenge[6]
	reqID[1] = askChallenge[7]

	fmt.Println("获得reqID:", reqID)

	challenge := askChallenge[34:]
	fmt.Println("获得challenge:", challenge)

	//生成reqAuth
	//生成chapPass开始，给authbuff使用
	chapPwd := mkChapPwd(reqID, challenge, config.Conf.User_pwd)
	fmt.Println("chapPwd:", chapPwd)
	//生成chapPass结束

	//生成authbuff开始，给reqAuth使用
	nameBytes := ([]byte)(config.Conf.User_name)
	nameLen := len(nameBytes)
	chapPwdLen := len(chapPwd)
	authbuff := make([]byte, 4 + nameLen + chapPwdLen + 6)

	authbuff[0] = 1		//AttrType为0x01，为username
	authbuff[1] = ((byte)(nameLen + 2))
	for i := 0; i < nameLen; i++  {
		authbuff[(2 + i)] = nameBytes[i]
	}

	authbuff[(2 + nameLen)] = 4	//AttrType为0x04，为chapPassWord
	authbuff[(3 + nameLen)] = ((byte)(chapPwdLen + 2))
	for i := 0; i < chapPwdLen; i++ {
		authbuff[(4 + nameLen + i)] = chapPwd[i]
	}

	authbuff[(4 + nameLen + chapPwdLen)] = 10		//AttrType为0x0a，是AC的IP
	authbuff[(4 + nameLen + chapPwdLen + 1)] = 6
	authbuff[(4 + nameLen + chapPwdLen + 2)] = basIP[0]
	authbuff[(4 + nameLen + chapPwdLen + 3)] = basIP[1]
	authbuff[(4 + nameLen + chapPwdLen + 4)] = basIP[2]
	authbuff[(4 + nameLen + chapPwdLen + 5)] = basIP[3]
	fmt.Println("authbuff:", authbuff)
	//生成authbuff结束

	reqAuth := make([]byte, 32)
	reqAuth[0] = 2
	reqAuth[1] = 3
	reqAuth[2] = 0
	reqAuth[3] = 0
	reqAuth[4] = serialNo[0]
	reqAuth[5] = serialNo[1]
	reqAuth[6] = reqID[0]
	reqAuth[7] = reqID[1]
	reqAuth[8] = userIP[0]
	reqAuth[9] = userIP[1]
	reqAuth[10] = userIP[2]
	reqAuth[11] = userIP[3]
	reqAuth[12] = 0
	reqAuth[13] = 0
	reqAuth[14] = 0
	reqAuth[15] = 3
	buf := make([]byte, 16)
	for i:=0; i<16; i++ {
		buf[i] = reqAuth[i]
	}

	reqAuthenticator := mkAuthen(buf, authbuff, config.Conf.Portal_key)
	fmt.Println("reqAuthenticator:", reqAuthenticator)

	for i:=0; i<16; i++ {
		reqAuth[16+i] = reqAuthenticator[i]
	}
	reqAuth = append(reqAuth, authbuff[0:]...)

	//发送reqAuth
	_, err = socket.Write(reqAuth)
	if err != nil {
		fmt.Println("发送数据失败!", err)
		xclog.Xclog.Println(err.Error())
		return
	}
	fmt.Println("Send reqAuth:", reqAuth)

	socket.SetReadDeadline(time.Now().Add(2 * time.Second))

	// 接收数据, 并判断请求Auth是否成功
	askAuth := make([]byte, 32)
	_, _, err = socket.ReadFromUDP(askAuth)
	if err != nil {
		fmt.Println("读取数据失败!", err)
		return
	}
	//fmt.Println("n:", n, " remoteAddr:", remoteAddr)
	fmt.Println("askAuth:", askAuth)

	if (askAuth[14] & 0xFF) == 0 || (askAuth[14] & 0xFF) == 2 {
		fmt.Println("发送reqAuth请求成功,准备发送affAckAuth")
	}
	if ((askAuth[14] & 0xFF) == 1) {
		fmt.Println("发送askAuth请求被拒绝")
		errLogOut(serialNo, reqID, userIP, basIP, socket)
		return
	}
	if ((askAuth[14] & 0xFF) == 3) {
		fmt.Println("系统繁忙，请稍后再试")
		errLogOut(serialNo, reqID, userIP, basIP, socket)
		return
	}
	if ((askAuth[14] & 0xFF) == 4) {
		fmt.Println("发送askAuth请求出现未知错误")
		errLogOut(serialNo, reqID, userIP, basIP, socket)
		return
	}

	//生成并发送affAckAuth给AC，确认认证成功
	affAckAuth := make([]byte, 38)

	affAckAuth[0] = 2
	affAckAuth[1] = 7
	affAckAuth[2] = 0
	affAckAuth[3] = 0
	affAckAuth[4] = serialNo[0]
	affAckAuth[5] = serialNo[1]
	affAckAuth[6] = reqID[0]
	affAckAuth[7] = reqID[1]
	affAckAuth[8] = userIP[0]
	affAckAuth[9] = userIP[1]
	affAckAuth[10] = userIP[2]
	affAckAuth[11] = userIP[3]
	affAckAuth[12] = 0
	affAckAuth[13] = 0
	affAckAuth[14] = 0
	affAckAuth[15] = 1

	for i := 0; i < 16; i++ {
		buf[i] = affAckAuth[i]
	}

	affAttrs := make([]byte, 6)
	affAttrs[0] = 10
	affAttrs[1] = 6
	affAttrs[2] = basIP[0]
	affAttrs[3] = basIP[1]
	affAttrs[4] = basIP[2]
	affAttrs[5] = basIP[3]

	affAuthen := mkAuthen(buf, affAttrs, config.Conf.Portal_key)
	for i := 0; i < 16; i++ {
		affAckAuth[(16 + i)] = affAuthen[i]
	}
	for i := 0; i < 6; i++ {
		affAckAuth[(32 + i)] = affAttrs[i]
	}

	//发送affAckAuth
	_, err = socket.Write(affAckAuth)
	if err != nil {
		fmt.Println("发送数据失败!", err)
		xclog.Xclog.Println(err.Error())
		return
	}
	fmt.Println("Send affAckAuth:", affAckAuth)
	fmt.Printf("IP[%s]认证成功\n", wlanuserip)
	SendResponse(ctx, "0", "认证成功")

	//将用户上线信息写入redis中
	redisdo := redisPool.Get()
	defer redisdo.Close()

	nowTime := time.Now().Unix()
	expDis, err := strconv.ParseInt(expired, 10, 64)
	if err != nil {
		xclog.Xclog.Println(err.Error())
		fmt.Println("字符串转数值型发生错误")
	}
	expTime := nowTime + expDis

	userMac := strings.Replace(wlanusermac, ":", "", -1)
	mac_hash := "PS_" + userMac
	_, err = redisdo.Do("hset", mac_hash, "userIP", wlanuserip)
	if err != nil {
		xclog.Xclog.Println(err.Error())
		fmt.Println("userIP写入redis失败")
		return
	}
	_, err = redisdo.Do("hset", mac_hash, "basIP", wlanacip)
	if err != nil {
		xclog.Xclog.Println(err.Error())
		fmt.Println("wlanacip写入redis失败")
		return
	}
	_, err = redisdo.Do("hset", mac_hash, "uptime", nowTime)
	if err != nil {
		xclog.Xclog.Println(err.Error())
		fmt.Println("nowTime写入redis失败")
		return
	}
	_, err = redisdo.Do("hset", mac_hash, "expired", expTime)
	if err != nil {
		xclog.Xclog.Println(err.Error())
		fmt.Println("expTime写入redis失败")
		return
	}
	fmt.Printf("mac[%s] IP[%s]认证信息成功写入redis", wlanusermac, wlanuserip)
}

func Logout(ctx *iris.Context) {
	fmt.Println("*****************************")
	wlanuserip := ctx.FormValueString("wlanuserip")
	wlanacip := ctx.FormValueString("wlanacip")
	fmt.Printf("wlanuserip = %s\nwlanacip = %s\n", wlanuserip, wlanacip)

	userIP := ipToBytes(wlanuserip)
	basIP := ipToBytes(wlanacip)
	serialNo := mkSerialNo(256)

	//udp协议，建立和AC的udp连接，进行下线的操作
	socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.IPv4(192, 168, 199, 1),
		Port: 2000,
	})
	if err != nil {
		fmt.Println("连接失败!", err)
		xclog.Xclog.Println(err.Error())
		return
	}
	defer socket.Close()

	askQuit := sendLogOut(serialNo, userIP, basIP, socket)

	if (askQuit[14] & 0xFF) == 0 {
		fmt.Printf("发送reqQuit请求成功, IP[%s]自请求下线成功\n", wlanuserip)
		SendResponse(ctx, "0", "请求下线成功")
	}
	if ((askQuit[14] & 0xFF) == 1) {
		fmt.Println("下线请求被拒绝")
		SendResponse(ctx, "3", "自请求下线失败")
		return
	}
	if ((askQuit[14] & 0xFF) == 2) {
		fmt.Println("未知原因下线失败")
		SendResponse(ctx, "3", "自请求下线失败")
		return
	}
}

func sendLogOut(serialNo, userIP, basIP []byte, socket *net.UDPConn) []byte {

	reqQuit := make([]byte, 38)
	reqQuit[0] = 2
	reqQuit[1] = 5
	reqQuit[2] = 0
	reqQuit[3] = 0
	reqQuit[4] = serialNo[0]
	reqQuit[5] = serialNo[1]
	reqQuit[6] = 0
	reqQuit[7] = 0
	reqQuit[8] = userIP[0]
	reqQuit[9] = userIP[1]
	reqQuit[10] = userIP[2]
	reqQuit[11] = userIP[3]
	reqQuit[12] = 0
	reqQuit[13] = 0
	reqQuit[14] = 0
	reqQuit[15] = 1

	buff := make([]byte, 16)
	for i := 0; i < 16; i++ {
		buff[i] = reqQuit[i]
	}

	attrs := make([]byte, 6)
	attrs[0] = 10
	attrs[1] = 6
	attrs[2] = basIP[0]
	attrs[3] = basIP[1]
	attrs[4] = basIP[2]
	attrs[5] = basIP[3]

	authen := mkAuthen(buff, attrs, config.Conf.Portal_key)
	for i := 0; i < 16; i++ {
		reqQuit[(16 + i)] = authen[i]
	}
	for i := 0; i < 6; i++ {
		reqQuit[(32 + i)] = attrs[i]
	}

	_, err := socket.Write(reqQuit)
	if err != nil {
		fmt.Println("发送数据失败!", err)
		xclog.Xclog.Println(err.Error())
		return nil
	}
	fmt.Println("Send reqQuit:", reqQuit)

	socket.SetReadDeadline(time.Now().Add(2 * time.Second))

	// 接收数据, 并判断请求reqQuit是否成功
	askQuit := make([]byte, 32)
	_, _, err = socket.ReadFromUDP(askQuit)
	if err != nil {
		fmt.Println("logout中ac返回的数据读取失败!", err)
		return nil
	}
	//fmt.Println("n:", n, " remoteAddr:", remoteAddr)
	fmt.Println("askQuit:", askQuit)

	return askQuit
}

func OverTime() {

	redisdo := redisPool.Get()
	defer redisdo.Close()

	socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.IPv4(192, 168, 199, 1),
		Port: 2000,
	})
	if err != nil {
		fmt.Println("连接失败!", err)
		xclog.Xclog.Println(err.Error())
		return
	}
	defer socket.Close()

	for {
		sret, err := redis.Strings(redisdo.Do("keys", "*")) //获取所有的键,取出字符串数组
		if err != nil {
			xclog.Xclog.Println(err.Error())
			continue
		}
		if len(sret) == 0 {
			continue
		} else {
			for _, v := range sret {
				if strings.Contains(v, "PS_") {
					expired, err := redis.String(redisdo.Do("hget", v, "expired"))
					if err != nil {
						xclog.Xclog.Println(err.Error())
						continue
					}

					expTimeInt64, err := strconv.ParseInt(expired, 10, 64)
					if err != nil {
						xclog.Xclog.Println(err.Error())
						continue
					}
					if time.Now().Unix() > expTimeInt64 {
						basIPStr, err := redis.String(redisdo.Do("hget", v, "basIP"))
						if err != nil {
							xclog.Xclog.Println(err.Error())
							continue
						}
						userIPStr, err := redis.String(redisdo.Do("hget", v, "userIP"))
						if err != nil {
							xclog.Xclog.Println(err.Error())
							continue
						}

						userMac := strings.TrimLeft(v, "PS_")
						userIP := ipToBytes(userIPStr)
						basIP := ipToBytes(basIPStr)
						serialNo := mkSerialNo(256)
						askQuit := sendLogOut(serialNo, userIP, basIP, socket)
						if (askQuit[14] & 0xFF) == 0 {
							fmt.Printf("userMAC[%s], userIP[%s]已经超时,踢下线成功\n", userMac, userIPStr)
							redisdo.Do("del", v)
						}
						if ((askQuit[14] & 0xFF) == 1) {
							fmt.Printf("userMAC[%s], userIP[%s]已经超时,下线请求被拒绝\n", userMac, userIPStr)
						}
						if ((askQuit[14] & 0xFF) == 2) {
							fmt.Printf("userMAC[%s], userIP[%s]已经超时,未知原因下线失败\n", userMac, userIPStr)
						}
					}

				}
			}
		}

	}

}

func errLogOut(serialNo, reqID, userIP, basIP []byte, socket *net.UDPConn) {

	reqErrQuit := make([]byte, 38)
	reqErrQuit[0] = 2
	reqErrQuit[1] = 5
	reqErrQuit[2] = 0
	reqErrQuit[3] = 0
	reqErrQuit[4] = serialNo[0]
	reqErrQuit[5] = serialNo[1]
	reqErrQuit[6] = reqID[0]
	reqErrQuit[7] = reqID[1]
	reqErrQuit[8] = userIP[0]
	reqErrQuit[9] = userIP[1]
	reqErrQuit[10] = userIP[2]
	reqErrQuit[11] = userIP[3]
	reqErrQuit[12] = 0
	reqErrQuit[13] = 0
	reqErrQuit[14] = 1
	reqErrQuit[15] = 1

	buff := make([]byte, 16)
	for i := 0; i < 16; i++ {
		buff[i] = reqErrQuit[i]
	}

	attrs := make([]byte, 6)
	attrs[0] = 10
	attrs[1] = 6
	attrs[2] = basIP[0]
	attrs[3] = basIP[1]
	attrs[4] = basIP[2]
	attrs[5] = basIP[3]

	authen := mkAuthen(buff, attrs, config.Conf.Portal_key)
	for i := 0; i < 16; i++ {
		reqErrQuit[(16 + i)] = authen[i]
	}
	for i := 0; i < 6; i++ {
		reqErrQuit[(32 + i)] = attrs[i]
	}

	_, err := socket.Write(reqErrQuit)
	if err != nil {
		fmt.Println("发送reqErrQuit数据失败!", err)
		xclog.Xclog.Println(err.Error())
		return
	}
	fmt.Println("Send reqErrQuit:", reqErrQuit)

	socket.SetReadDeadline(time.Now().Add(2 * time.Second))

	// 接收数据askQuit
	askQuit := make([]byte, 32)
	_, _, err = socket.ReadFromUDP(askQuit)
	if err != nil {
		fmt.Println("errLogOut中ac返回的数据读取失败!", err)
		return
	}
	//fmt.Println("n:", n, " remoteAddr:", remoteAddr)
	fmt.Println("errLogOut中的askQuit:", askQuit)

}

//将IP字符串转换成字节切片返回
func ipToBytes(ip string) []byte {
	ipStrs := strings.Split(ip, ".")
	userIp := make([]byte, 4)

	for i := 0; i < 4; i++ {
		a, err := strconv.ParseInt(ipStrs[i], 10, 64)
		if err != nil {
			xclog.Xclog.Println(err.Error())
			return nil
		}

		b := strconv.FormatInt(a, 16)
		if a < 16 {
			b = "0" + b
		}

		c, err := hex.DecodeString(b)
		if err != nil {
			xclog.Xclog.Println(err.Error())
			fmt.Println("ip转换成16进制显示的字符串错误")
			return nil
		}
		userIp[i] = c[0]

		//fmt.Println("userIp:", userIp[i])
	}

	return userIp
}

//随机生成两个字节并且返回
func mkSerialNo(limit int64) []byte {
	serialNo := make([]byte, 2)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 2; i++ {
		randInt := r.Int63n(limit)
		a := strconv.FormatInt(randInt, 16)

		if randInt < 16 {
			a = "0" + a
		}

		b, err := hex.DecodeString(a)
		if err != nil {
			xclog.Xclog.Println(err.Error())
			return nil
		}
		serialNo[i] = b[0]
	}

	return serialNo
}

//MD5加密生成16字节的Authen
func mkAuthen(buff, attrs []byte, portalKey string) []byte {
	key := ([]byte)(portalKey)
	buf := make([]byte, 0)
	a := append(attrs, key[0:]...)
	b := make([]byte, 16)
	c := append(b, a[0:]...)
	buf = append(buff, c[0:]...)

	//fmt.Println("mkAuthen beforeMD5:", buf)

	md5ctx := md5.New()
	md5ctx.Write(buf)
	auth := md5ctx.Sum(nil)

	return auth
}

//MD5加密生成16字节的Chap_PassWord
func mkChapPwd(reqID, challenge []byte, pwd string) []byte {

	buf := make([]byte, 0)
	buf = append(buf, reqID[1])
	usp := ([]byte)(pwd)
	buf = append(buf, usp[0:]...)
	buf = append(buf, challenge[0:]...)

	//fmt.Println("mkChapPwd beforeMD5:", buf)

	md5ctx := md5.New()
	md5ctx.Write(buf)
	chapPwd := md5ctx.Sum(nil)

	return chapPwd
}
