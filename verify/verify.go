package verify

import (
    "bytes"
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/binary"
    "encoding/hex"
    "errors"
    "strconv"
    "log"
    "os"
    "path/filepath"
	"net"
	"encoding/base32"
	"sync"
	"time"
	"io"
	"github.com/stalltrix/kep-demo/ntp"
	"hash/fnv"
	"github.com/stalltrix/kep-demo/kepdb"
	"github.com/stalltrix/kep-demo/kepresolv"
)

var BaseDir string

type ParsedMDB struct {
    Tag     uint16
    HashHex string
    PointTo string
    Raw     []byte
}

type dnsCache struct {
    key []byte
	des []uint64
	lastcache int64
}

var (
	mainkey_cache sync.Map
	ttlMap sync.Map
	known_keys sync.Map
)

func NewTTLMap(){
	exePath, err := os.Executable()
    if err == nil {
        BaseDir = filepath.Join(filepath.Dir(exePath), "kep-data")
		kepdb.Init_path(filepath.Dir(exePath))
    }else{
		 log.Println("walk database dir err:",err)
		 BaseDir = "kep-data"
	}
for {
	time.Sleep(time.Second *60*60)
	var newMap sync.Map
	var newCache sync.Map
	ttlMap=newMap
	mainkey_cache=newCache
}
}


func readExactly(r *bytes.Reader, n int) ([]byte,error) {
	if n <0 {
		return nil,errors.New("n<0")
	}else if n == 0 {
		return nil,nil
	}
    buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
    if err != nil {
        return nil,err;
    }
    return buf,nil
}

func desLookup(domain string) ([]uint64,error) {
	txtRecords, err := net.LookupTXT(domain)
    if err != nil {
        return nil,err
    }
	
	var resp []uint64
	
	for _, txt := range txtRecords {
	//log.Println("txt=",txt)
		if len(txt) >= 4 && txt[:4] == "des=" {
			v, err := strconv.ParseUint(txt[4:], 16, 64)
			if err != nil {continue;}
			resp = append(resp,v)
		}
    }
	if len(resp) == 0 {
		return nil,errors.New("nslookup pkey_des not found.")
	}
	return resp,nil
}

func dnsLookup(domain string) ([]byte,error) {
	txtRecords, err := net.LookupTXT(domain)
    if err != nil {
        return nil,err
    }
	
	for _, txt := range txtRecords {
	//log.Println("txt=",txt)
		if len(txt) >= 4 && txt[:4] == "kep=" {
			encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
			decoded, err := encoding.DecodeString(txt[4:])
			if err != nil {return nil,err;}
			return decoded,nil
		}
    }
	return nil,errors.New("nslookup mainkey not found.")
}

func Non_Plain_text(r io.Reader, n int) error {
    buf := make([]byte, n)
    _, err := io.ReadFull(r, buf)
    if err != nil {
        return err
    }
    for _, b := range buf {
        if b < 128 {
            if (b < 32 && b != '\n' && b != '\r' && b != '\t') || b == 127 {
                return errors.New("Non Plain text")
            }
        }
    }

    return nil
}

func bytesToInt64(b []byte) int64 {
    if len(b) != 5 {
       return -1
    }
    var t uint64
    t |= uint64(b[0]) << 32
    t |= uint64(b[1]) << 24
    t |= uint64(b[2]) << 16
    t |= uint64(b[3]) << 8
    t |= uint64(b[4])

    return int64(t)
}

func parseAndVerify(data []byte) (*ParsedMDB, error) {
    r := bytes.NewReader(data)

    version,err := r.ReadByte() // version
	if err !=nil {
		return nil, err
	}
		
	if version != 1 {
		return nil, errors.New("unsupported version")
	}
	
    hashType, err := r.ReadByte()
	if err !=nil {
		return nil, err
	}
    domainLen, err := r.ReadByte()
	if err !=nil {
		return nil, err
	}
	
	if domainLen == 0 {
		return nil, errors.New("domainlen=0")
	}
	
	timestamp,err:=readExactly(r, 5) //这里要检查时间窗口
	if err !=nil {
		return nil, err
	}
	
	post_time := bytesToInt64(timestamp)
	
	now_time := ntp.Get_Now_Time()
	
	offset_t:=now_time - post_time //sha256
	
	offset_t /= 60;
	
	if offset_t > 15 || offset_t < -15 {
		return nil, errors.New("timestamp out-of-time")
	}
	
	
	newdata,err:=readExactly(r, 2)
	if err !=nil {
		return nil, err
	}
    length := binary.BigEndian.Uint16(newdata) //正文长度

    mainKey,err := readExactly(r, 32)
	if err !=nil {
		return nil, err
	}
    pkey,err := readExactly(r, 32)
	if err !=nil {
		return nil, err
	}
    signKey,err := readExactly(r, 64)
	if err !=nil {
		return nil, err
	}

    _,err=r.ReadByte() // typeID
	if err !=nil {
		return nil, err
	}
	
    pointLen, err := r.ReadByte()
	if err !=nil {
		return nil, err
	}
    
	tag1,err:=readExactly(r, 2)
	if err !=nil {
		return nil, err
	}
	tagnum := binary.BigEndian.Uint16(tag1)

    cp,err:=r.ReadByte() // compress
	if err !=nil {
		return nil, err
	}
	if cp !=0 {
		return nil, errors.New("unsupported compress")
	}

	domain_str,err:=readExactly(r, int(domainLen))
	if err !=nil {
		return nil, err
	}
	
	for i:=0; i<int(domainLen);i++ {
        c := domain_str[i]
        if (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '.' || c == '-' {
            continue
        }
        return nil, errors.New("invalid character in domain")
    }
	
	if domain_str[len(domain_str)-1] == '.' {
        return nil, errors.New("domain must not end with '.'")
    }
	
	var mainPub []byte
	var dns_cached *dnsCache
	val,ok:=mainkey_cache.Load(string(domain_str))
	if ok {
		dns_cached=val.(*dnsCache)
		mainPub=dns_cached.key
	} else {
		mainPub,err=dnsLookup(string(domain_str))
		if err !=nil {
			return nil, err
		}
		dns_cached=&dnsCache{
			key: mainPub,
		}
		mainkey_cache.Store(string(domain_str),dns_cached);
	}
	
    pointToRaw,err := readExactly(r, int(pointLen))
	if err !=nil {
		return nil, err
	}
	
	err = Non_Plain_text(r,int(length))
	
	if err !=nil {
		return nil, err
	}

	if len(data) < 99 {
		return nil, errors.New("msg too short")
	}
    hashEnd := len(data) - (32 + 64 + 2 + 1)
    hashData := data[:hashEnd]

    var calcHash []byte
    switch hashType {
    case 1:
        h := sha256.Sum256(hashData)
        calcHash = h[:]
    default:
        return nil, errors.New("unsupported hash type")
    }

    tHash,err := readExactly(r, 32)
	if err !=nil {
		return nil, err
	}
    signature,err := readExactly(r, 64)
	if err !=nil {
		return nil, err
	}
	tag2,err:=readExactly(r, 2)
	if err !=nil {
		return nil, err
	}
    tag2num := binary.BigEndian.Uint16(tag2)
	if tagnum != tag2num{
		log.Println("Debug: tag change: tagnum != tag2num")
	}
	
    ttl,err := r.ReadByte() // ttl
	if err !=nil {
		return nil, err
	}
	if ttl > 250 || ttl == 0 {
		 return nil, errors.New("ttl err")
	}
	
	_,err= r.ReadByte()
	if err == nil {
		//已读完
		return nil, errors.New("msg too long")
	}

    // ===== 校验 =====
    if !bytes.Equal(mainKey, mainPub) {
        return nil, errors.New("mainkey mismatch")
    }

    if !ed25519.Verify(mainPub, pkey, signKey) {
        return nil, errors.New("mainkey -> pkey signature invalid")
    }

    if !bytes.Equal(calcHash, tHash) {
        return nil, errors.New("t_hash mismatch")
    }

    if !ed25519.Verify(pkey, tHash, signature) {
        return nil, errors.New("post signature invalid")
    }
	
	_,ok=ttlMap.Load(string(tHash))
	if ok {
		//重复,去重
		return nil, errors.New("msg already exist")
	}
	
		
	//验证摘要
	h := fnv.New64a()
    h.Write(pkey)
	now_des:=h.Sum64()
	if dns_cached.des==nil{
		des_s,err:=desLookup(string(domain_str))
		if err!=nil {
			return nil, err
		}
		dns_cached.des=des_s
		dns_cached.lastcache=now_time
	}
	
	is_des_verify:=false
	
	for _, des_num := range dns_cached.des {
        if des_num == now_des {
            is_des_verify= true
			break
        }
    }
	
	if !is_des_verify {
		if dns_cached.lastcache+120 > now_time {
			return nil, errors.New("pkey des not found in cache")
		}else{
			des_s,err:=desLookup(string(domain_str))
			if err!=nil {
				return nil, err
			}
			dns_cached.des=des_s
			dns_cached.lastcache=now_time
			for _, des_num := range dns_cached.des {
				if des_num == now_des {
					is_des_verify= true
					break
				}
			}
			if !is_des_verify {
				return nil, errors.New("pkey des not found in renew")
			}
		}
	}
	if tagnum >=65534 {
		if tagnum != tag2num{
			return nil, errors.New("tag changed, invalid")
		}
	}
	
	ttlMap.Store(string(tHash),struct{}{})

    hashHex := hex.EncodeToString(tHash)

    var parent string
    if len(pointToRaw) >4 {
        parent = hex.EncodeToString(pointToRaw)
		err = ensureParent(parent)
		if err !=nil {
			return nil, err
		}
    } else {
		if tagnum ==65534 {
			return nil, errors.New("tag changed, invalid")
		}
		path := filepath.Join(
			BaseDir,
			"index",
			parent+".txt",
		)
		f, err := os.Create(path)
		if err == nil {
			f.Close()
		}
	}
	
	if tagnum ==65534 || len(parent)>64{
		child:=parent
		if len(child)>64{
			child=child[:64]
		}
		hexbyte,err:=kepdb.ReadHash(child)
		if err!=nil{
			return nil, err
		}
		_,ori_domain,_,_,_,ori_key_des,_,_,_,_,err:=kepresolv.Resolv(hexbyte)
		if err!=nil{
			return nil, err
		}
		key_des := binary.BigEndian.Uint64(mainPub[:8])
		if !(bytes.Equal(ori_domain,domain_str) && (ori_key_des==key_des)){
			return nil, errors.New("tag changed key not match")
		}
	}
	
    return &ParsedMDB{
        Tag:     tag2num,
        HashHex: hashHex,
        PointTo: parent,
        Raw:     data,
    }, nil
}

func ensureParent(parent string) error {
	if parent=="" {
		return nil
	}
	var child string
	if len(parent)>64{
		child=parent[:64]
		parent=parent[64:]
	}
	path := filepath.Join(
        BaseDir,
        "index",
        parent+".txt",
    )
	_, err := os.Stat(path)
    if err == nil {
		if child == "" {
			return nil
		}
        data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(child)) {
			return nil
		}
		return errors.New("Discard dangling non-child item:"+child)
    }
    return errors.New("Discard dangling pointer:"+parent)
	
}

func ensureDir(path string) error {
    return os.MkdirAll(path, 0755)
}

func writeMDB(p *ParsedMDB) error {
    dir := filepath.Join(BaseDir, strconv.Itoa(int(p.Tag)))
    if err := ensureDir(dir); err != nil {
        return err
    }

    mdbPath := filepath.Join(dir, p.HashHex+".mdb")
    if err := os.WriteFile(mdbPath, p.Raw, 0644); err != nil {
        return err
    }

    idxPath := filepath.Join(BaseDir, "tag_"+strconv.Itoa(int(p.Tag))+".idx")

    f, err := os.OpenFile(idxPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
    if err != nil {
        return err
    }
    defer f.Close()

    if _, err := f.WriteString(p.HashHex + "\n"); err != nil {
        return err
    }

    return nil
}

func appendSubIndex(tag uint16, parent, child string) error {
    root:=false
	if parent == "" {
		if child !="" {
			parent=child
			root=true
		}else{
			return nil
		}
    }

    path := filepath.Join(
        BaseDir,
        "index",
        parent+".txt",
    )
	if root {
		f, err := os.Create(path)
   	 	if err != nil {
   	    	return err
   		}
   		f.Close()
		return nil
	}

    f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
    if err != nil {
        return err
    }
    defer f.Close()
    _, err = f.WriteString(child + ";")
    return err
}

func IngestMDB(data []byte) error {

    parsed, err := parseAndVerify(data)
    if err != nil {
        return err
    }
	err = writeMDB(parsed);
    if err != nil {
        return err
    }

    if err := appendSubIndex(parsed.Tag, parsed.PointTo, parsed.HashHex); err != nil {
        return err
    }

    log.Println("Debug: ingested:", parsed.HashHex)
    return nil
}