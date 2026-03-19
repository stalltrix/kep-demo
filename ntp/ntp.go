package ntp   

import (
	"encoding/binary"
	"net"
	"time"
	"io"
	"errors"
	"log"
)   

const ntpEpochOffset = 2208988800   
var offsetTime int64
var ntp_server string

func getNTPTime() (time.Time, error) {
 conn, err := net.DialTimeout("udp", ntp_server,15*time.Second)
 if err != nil {
     return time.Time{}, err
 }
 defer conn.Close()
 req := make([]byte, 48)
 req[0] = 0x1B
 if _, err := conn.Write(req); err != nil {
     return time.Time{}, err
 }
 resp := make([]byte, 48)
 conn.SetDeadline(time.Now().Add(15*time.Second))
 _, err = io.ReadFull(conn,resp);
 if err != nil {
     return time.Time{}, err
 }
 mode := resp[0] & 0x7
 if mode !=4 {
	 return time.Time{},errors.New("ntp mode !=4")
 }
 if resp[1] == 0 || resp[1] > 15 {
	 return time.Time{},errors.New("ntp Death data")
 }
 secs := binary.BigEndian.Uint32(resp[40:44])
 frac := binary.BigEndian.Uint32(resp[44:48])
 sec := int64(secs) - ntpEpochOffset
 nsec := (int64(frac) * 1e9) >> 32
 if sec==0 {
	  return time.Time{},errors.New("ntp sec==0")
 }

 return time.Unix(sec, nsec), nil
}   

func Get_Now_Time() int64 {
	t:=time.Now().Unix()
	t+=offsetTime
	return t
}

func ntp_sync() {
for{
	t, err := getNTPTime()
	if err != nil {
		log.Println(err)
		time.Sleep(time.Second*60*5)
		continue;
	}
	offsetTime = t.Unix() - time.Now().Unix()
	time.Sleep(time.Second*60*60*24)
}
}

func Ntp_Init(server string){
	if server != "" {
	ntp_server=server+":123"
	go ntp_sync()
	}
}