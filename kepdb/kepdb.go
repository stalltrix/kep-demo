package kepdb

import (
    "bytes"
    "errors"
    "io/fs"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"
	"strconv"
	"io"
)

var (
    BaseDir   = "kep-data"
    CacheTTL  = 5 * time.Minute
    MaxTagNum = 512
)

type cacheItem struct {
    value    interface{}
    expireAt time.Time
}

var cache sync.Map

func cacheGet(key string) (interface{}, bool) {
    if v, ok := cache.Load(key); ok {
        item := v.(cacheItem)
        if time.Now().Before(item.expireAt) {
            return item.value, true
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
    cacheKey := "hash:" + hash
    if v, ok := cacheGet(cacheKey); ok {
        return v.([]byte), nil
    }

    path, err := findHashFile(hash)
    if err != nil {
        return nil, err
    }

    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    cacheSet(cacheKey, data)
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

    const lineSize = 65 // 32 hex + '\n'

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
    return FindALLFile(hash + ".mdb")
}

func findSubFile(hash string) (string, error) {
    return FindFile(hash + ".txt")
}

func FindALLFile(name string) (string, error) {
    var found string
    err := filepath.WalkDir(BaseDir, func(path string, d fs.DirEntry, err error) error {
        if err != nil {
            return err
        }
        if !d.IsDir() && d.Name() == name {
            found = path
            return fs.SkipDir
        }
        return nil
    })

    if err != nil {
        return "", err
    }
    if found == "" {
        return "", errors.New("allfile not found: " + name)
    }
    return found, nil
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

func itoa(i int) string {
    return strconv.Itoa(i)
}

func Init_path(self string){
    if self != "" {
        BaseDir = filepath.Join(self, "kep-data")
    }
}