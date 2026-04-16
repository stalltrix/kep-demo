package limit

import (
	"sync"
	"time"
	"sync/atomic"
)

var (
	limiterMap sync.Map
)

func GetLimit(key string) int32 {
	val,ok:=limiterMap.Load(key)
	if ok {
		num:=atomic.AddInt32(val.(*int32), 1)
		return num
	}
	var a int32
	val,_=limiterMap.LoadOrStore(key,&a)
	return atomic.LoadInt32(val.(*int32))
}

func clean_limit(){
for {
	time.Sleep(12*time.Hour)
	var a sync.Map
	limiterMap=a
}
}

func init(){
	go clean_limit()
}