package send

import "log"

type NextMsg struct {
    Addr string
    Auth string
}

var (
	nextloop []NextMsg
)

func change_Packet(Msg []byte) []byte {
	length:=len(Msg)
	ttl:=Msg[length-1]
	ttl--
	if ttl ==0 || ttl > 250 {
		return nil
	}
	Msg[length-1]=ttl
    return Msg
}

func Nextmsg(msg []byte) error {
	newMsg:=change_Packet(msg)
	if newMsg == nil {
		return nil
	}
	for i:=range nextloop {
		client := NewMsgClient(nextloop[i].Addr, nextloop[i].Auth)
		_,err:=client.Send("data", newMsg)
		client.Close()
		if err !=nil {
		log.Println("send err",err)
		}
		log.Println("send to",nextloop[i].Addr)
	}
	return nil
}

func Send_Init(nextServer []NextMsg) {
	nextloop=nextServer
}