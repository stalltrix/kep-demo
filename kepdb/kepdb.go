package kepdb

import (
    "bytes"
    "errors"
    //"io/fs"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"
	"strconv"
	"io"
	"encoding/hex"
	"github.com/stalltrix/kep-demo/logger"
)

var (
    BaseDir   = "kep-data"
    CacheTTL  = 5 * time.Minute
    MaxTagNum = 512
	log logger.Log_TYPE
	is_init bool
)

type cacheItem struct {
    value    interface{}
    expireAt time.Time
}

type cacheIdx struct {
    dataMap map[uint16]struct{} //概率性 hashMap
	lock sync.RWMutex
}

var (
	cache sync.Map
	usedTags []int
	path_log map[uint16]*cacheIdx
	prefixMap sync.Map
)

func clean_ttl(){
for{
	time.Sleep(time.Hour*8)
	will_del_data:=make([]string,0,16)
	now:=time.Now()
	cache.Range(func(k, v interface{}) bool {
		key:=k.(string)
		val := v.(cacheItem)
		if now.After(val.expireAt.Add(6 * time.Hour)) {
			will_del_data=append(will_del_data,key)
		}
		return true
	})
	for _,key:=range will_del_data {
		cache.Delete(key)
	}
	will_del_data=nil
}
}

func cacheGet(key string) (interface{}, bool) {
    if v, ok := cache.Load(key); ok {
        item := v.(cacheItem)
		if len(key) > 5 && key[:5] == "find:" {
			if time.Now().Before(item.expireAt.Add(time.Hour)) {
				return item.value, true
			}
		}else{
        if time.Now().Before(item.expireAt) {
            return item.value, true
        }
		}
        cache.Delete(key)
    }
    return nil, false
}

func cacheSet(key string, val interface{}) {
    cache.Store(key, cacheItem{
        value:    val,
        expireAt: time.Now().Add(CacheTTL),
    })
}

func ReadHash(hash string) ([]byte, error) {
    path, err := findHashFile(hash)
    if err != nil {
        return nil, err
    }

    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    return data, nil
}

func ReadTag(tag int) ([]string, error) {
    cacheKey := "tag:" + strconv.Itoa(tag)
    if v, ok := cacheGet(cacheKey); ok {
        return v.([]string), nil
    }

    idxPath := filepath.Join(BaseDir, "tag_"+strconv.Itoa(tag)+".idx")

    f, err := os.Open(idxPath)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    st, err := f.Stat()
    if err != nil {
        return nil, err
    }

    const lineSize = 65 // 64 hex + '\n'

    size := st.Size()
    count := int(size / lineSize)

    limit := MaxTagNum
    if count < limit {
        limit = count
    }

    offset := size - int64(limit*lineSize)
    if offset < 0 {
        offset = 0
    }

    buf := make([]byte, limit*lineSize)
    _, err = f.ReadAt(buf, offset)
    if err != nil && err != io.EOF {
        return nil, err
    }

    result := make([]string, 0, limit)

    for i := limit - 1; i >= 0; i-- {
        start := i * lineSize
        hash := string(buf[start : start+64])
        result = append(result, hash)
    }

    cacheSet(cacheKey, result)
    return result, nil
}

func ReadSub(hash string) ([]string, error) {
    cacheKey := "sub:" + hash
    if v, ok := cacheGet(cacheKey); ok {
        return v.([]string), nil
    }

    txtPath, err := findSubFile(hash)
    if err != nil {
        return nil, err
    }

    data, err := os.ReadFile(txtPath)
    if err != nil {
        return nil, err
    }

    lines := bytes.Split(bytes.TrimSpace(data), []byte(";"))
    var subs []string
    for _, l := range lines {
        s := strings.TrimSpace(string(l))
        if s != "" {
            subs = append(subs, s)
        }
    }

    cacheSet(cacheKey, subs)
    return subs, nil
}

func findHashFile(hash string) (string, error) {
	cacheKey := "find:" + hash
    if v, ok := cacheGet(cacheKey); ok {
        return v.(string), nil
    }
	
	files,err:=FindALLFile(hash + ".mdb")
	if err!=nil{
		return "",err
	}
	
	cacheSet(cacheKey, files)
	return files,nil
}

func findSubFile(hash string) (string, error) {
    return FindFile(hash + ".txt")
}

func FindALLFile(name string) (string, error) {
	found,ok:=findFileByIndex(name)
	if ok {
		if _, err := os.Stat(found); err != nil {
			return "", err
		}
		return found, nil
	}
	return "", errors.New("file not found: " + name)
	/*log.Println("miss Idx cache:",name)
	var foundErr = errors.New("found")
    err := filepath.WalkDir(BaseDir, func(path string, d fs.DirEntry, err error) error {
        if err != nil {
            return err
        }
        if !d.IsDir() && d.Name() == name {
            found = path
            return foundErr
        }
        return nil
    })
	
	if err == foundErr {
		return found,nil
	}

    if err != nil {
        return "", err
    }
    if found == "" {
        return "", errors.New("allfile not found: " + name)
    }
    return found, nil*/
}

func findFileByIndex(name string) (string,bool){
	hexStr := strings.TrimSuffix(name, ".mdb")
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		log.Println("format hex err:",err)
		return "",false
	}
	if len(b) != 32 {
		return "",false
	}
	var key uint16
	key=uint16(b[0])<<8|uint16(b[1])
	
	tag,ok:=prefixMap.Load(key)
	if ok {
		//可能存在
		found:=filepath.Join(BaseDir, strconv.Itoa(int(tag.(uint16))), name)
		if _, err := os.Stat(found); err == nil {
			return found,true
		}
	}
		
	for _,i:=range usedTags {
		nowPath,ok:=path_log[uint16(i)]
		if !ok {
			continue;
		}
		
		nowPath.lock.RLock()
		_,ok=nowPath.dataMap[key]
		nowPath.lock.RUnlock()
		if ok {
			//大概率存在
			found:=filepath.Join(BaseDir, strconv.Itoa(i), name)
			if _, err := os.Stat(found); err == nil {
				return found,true
			}
		}
		
		idxPath := filepath.Join(BaseDir, "tag_"+strconv.Itoa(i)+".idx")
		newdata, err := os.ReadFile(idxPath)
		if err != nil {
			log.Println("kepdb: can't open Index file:",err)
			continue;
		}
		
		if bytes.Contains(newdata, []byte(hexStr)) {
			nowPath.lock.Lock()
			nowPath.dataMap[key]=struct{}{}
			nowPath.lock.Unlock()
			prefixMap.Store(key,uint16(i))
			found:=filepath.Join(BaseDir, strconv.Itoa(i), name)
			return found,true
		}
	}
	return "",false
}

func FindFile(name string) (string, error) {
    path := filepath.Join(BaseDir, "index", name)

    if _, err := os.Stat(path); err != nil {
        if os.IsNotExist(err) {
            return "", errors.New("file not found: " + path)
        }
        return "", err
    }

    return path, nil
}

func index_Init(){
	path_log=make(map[uint16]*cacheIdx)
	usedTags=usedTags[:0]
	files, err := filepath.Glob(filepath.Join(BaseDir, "tag_*.idx"))
	if err != nil {
		log.Println("init idx err:",err)
		return
	}
	for _, f := range files {
		name := filepath.Base(f)
		idstr := strings.TrimSuffix(strings.TrimPrefix(name,"tag_"),".idx")
		i, err := strconv.Atoi(idstr)
        if err != nil {
            continue
        }
		if i<0||i>65535{
			continue
		}
		idxPath := filepath.Join(BaseDir, "tag_"+strconv.Itoa(i)+".idx")

		usedTags=append(usedTags,i)
		New_cacheIdx:=&cacheIdx{
			dataMap: make(map[uint16]struct{}),
		}
		path_log[uint16(i)]=New_cacheIdx

		newdata, err := os.ReadFile(idxPath)
		if err != nil {
			log.Println("kepdb: can't open Index file:",err)
			continue;
		}
		var b [2]byte
		for offset:=0;offset+5<len(newdata);offset+=65{
			hex.Decode(b[:], newdata[offset:offset+4])
			key:=uint16(b[0])<<8|uint16(b[1])
			New_cacheIdx.dataMap[key]=struct{}{}
			prefixMap.Store(key,uint16(i))
		}
	}
}

func init(){
	log.SetLevel("info")
	go clean_ttl()
	go check_init()
}

func check_init(){
<-time.After(8 * time.Second)
if !is_init{
	log.Println("WARN: database not init")
	index_Init()
}
}

func Init_path(self string){
    if self != "" {
        BaseDir = filepath.Join(self, "kep-data")
    }
	is_init=true
	index_Init()
}