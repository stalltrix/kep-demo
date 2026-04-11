package verify

import (
	"sync"
)

var (
	internalLock [256]sync.Mutex
)

func FdLock(fd byte) {
	internalLock[fd].Lock()
}

func FdUnlock(fd byte){
	internalLock[fd].Unlock()
}