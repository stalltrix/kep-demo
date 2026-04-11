package pbb

import (
    "sync"
    "sync/atomic"
	"hash/maphash"
	"math/rand"
	"time"
)

const cleanupSize = 65536
const maxKeys = int64(1 << 17)
const ringSize = uint64(1 << 18)

var rnd *rand.Rand

type Cache struct {
    m sync.Map

    keys []uint64
    mask uint64

    writePos atomic.Uint64
    size     atomic.Int64
	lock     atomic.Bool

	s maphash.Seed
}

func NewMap() *Cache {
	seed := maphash.MakeSeed()
    return &Cache{
        keys:        make([]uint64, ringSize),
        mask:        ringSize - 1,
		s: seed,
    }
}

func (c *Cache) Store(input string, v interface{}) {
	var h maphash.Hash
	h.SetSeed(c.s)
	h.WriteString(input)
	key:=h.Sum64()
	if key == 0 {
		return
	}
    _, loaded := c.m.LoadOrStore(key, v)
    if loaded {
        c.m.Store(key, v)
        return
    }

    c.size.Add(1)

    pos := c.writePos.Add(1)
    c.keys[pos&c.mask] = key
	
	newsize:=c.size.Load()
    if newsize > maxKeys {
		if newsize > int64(ringSize)-8192 {
			//爆环了
			c.randClean()
		} else {
			c.cleanup()
		}
    }
}

func (c *Cache) Load(input string) (interface{}, bool) {
	var h maphash.Hash
	h.SetSeed(c.s)
	h.WriteString(input)
	key:=h.Sum64()
	if key == 0 {
		return nil,false
	}
    return c.m.Load(key)
}

func (c *Cache) Delete(input string) {
	var h maphash.Hash
	h.SetSeed(c.s)
	h.WriteString(input)
	key:=h.Sum64()
	if key == 0 {
		return
	}
	if _, ok := c.m.LoadAndDelete(key); ok {
		c.size.Add(-1)
	}
}

func (c *Cache) cleanup() {
    ok := c.lock.CompareAndSwap(false, true)
	if !ok {
		return
	}
	defer c.lock.Store(false)
	
    if c.size.Load() <= maxKeys {
        return
    }

    write := c.writePos.Load()
	
	if write <= cleanupSize {
		return
	}

    limit := write - uint64(cleanupSize)

    for i := 0; i < cleanupSize*2; i++ {
        idx := Rand_get() % limit
        k := c.keys[idx&c.mask]
        if k == 0 {
            continue
        }
		i++
        if _, ok := c.m.LoadAndDelete(k); ok {
            c.size.Add(-1)
			c.keys[idx&c.mask]=0
        }
    }
}

func (c *Cache) randClean() {
    ok := c.lock.CompareAndSwap(false, true)
	if !ok {
		return
	}
	defer c.lock.Store(false)
	c.m.Range(func(k, v interface{}) bool {
		if Rand_get()&1 == 1 {
			key:=k.(uint64)
			if _,ok := c.m.LoadAndDelete(key); ok {
				c.size.Add(-1)
			}
		}
		return true
	})
}

func Rand_get() uint64 {
	return rnd.Uint64()
}

func init(){
	rnd=rand.New(rand.NewSource(time.Now().UnixNano()))
}