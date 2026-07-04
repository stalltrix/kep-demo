package psl

import (
	"os"
	"errors"
	"strings"
	"golang.org/x/net/publicsuffix"
	"github.com/stalltrix/kep-demo/logger"
)

var (
	domain_list=make(map[string]byte)
	domain_allow_one=make(map[string]bool)
	log logger.Log_TYPE
	list_init bool
)

func init(){
	log.SetLevel("info")
}

func Init_list(filename string) error {
	if list_init {
		return errors.New("list already loaded")
	}
    data, err := os.ReadFile(filename)
    if err != nil {
        return err
    }
	list_init=true
    content := string(data)
	content=strings.ReplaceAll(content, " ", "")
	content=strings.ReplaceAll(content, "\r", "")
	content=strings.ReplaceAll(content, "\t", "")
    lines := strings.Split(content, "\n")
    for _, line := range lines {
        if line == "" {
            continue
        }
		if line[0]=='#'||line[0]==';'{
			continue
		}
        parts := strings.Split(line, ",")
        if len(parts) != 2 {
            continue
        }
        typeParts := strings.Split(parts[1], "=")
        if len(typeParts) != 2 {
            continue
        }
		if typeParts[0]=="type" {
			if (typeParts[1]=="white"||typeParts[1]=="allow"||typeParts[1]=="public"){
				log.Printf("info: Load root_domain:%s as public\n",parts[0])
				if !strings.HasPrefix(parts[0], "*.") {
					suffix, err := publicsuffix.EffectiveTLDPlusOne(parts[0])
					if err!=nil {
						return err
					}
					val,ok:=domain_list[suffix]
					if ok && val==3 {
						domain_allow_one[parts[0]]=false
						domain_list[suffix]=4;
					} else {
						domain_allow_one[parts[0]]=false
						domain_list[suffix]=2;
					}
					continue
				}
				
				domain_allow:=strings.TrimPrefix(parts[0], "*.")
				suffix, err := publicsuffix.EffectiveTLDPlusOne(domain_allow)
				if err!=nil {
					return err
				}
				
				domain_allow_one[domain_allow]=true
				domain_list[suffix]=1;
			} else if (typeParts[1]=="ban"||typeParts[1]=="block"||typeParts[1]=="black"||typeParts[1]=="deny"){
				if strings.HasPrefix(parts[0], "*.") {
					parts[0]=strings.TrimPrefix(parts[0], "*.")
				}
				log.Printf("info: Load root_domain:%s as general\n",parts[0])
				suffix, err := publicsuffix.EffectiveTLDPlusOne(parts[0])
				if err==nil {
					return errors.New("can't use subTLD for deny rule: "+parts[0])
				} else {
					if !strings.Contains(err.Error(), "cannot derive eTLD+1") {
						return err
					}
					suffix=parts[0]
				}
				
				val,ok:=domain_list[suffix]
				if ok && val==2 {
					domain_list[suffix]=4;
				} else {
					domain_list[suffix]=3;
				}
			} else {
				return errors.New("type not found")
			}
		}
    }
	return nil
}

func Check_psl(root_domain string) (int,bool) {
	if !list_init {return -1,false;}
	
	public_suffix,_:= publicsuffix.PublicSuffix(root_domain)
	
	val,ok:=domain_list[root_domain]
	val2,ok2:=domain_list[public_suffix]
	
	if !ok && !ok2 {
		return -1,false
	}
	if ok {
		return int(val),true
	}
	return int(val2),ok2
}

func Check_allowOne(domain string) bool {
	val,ok:=domain_allow_one[domain]
	return ok && !val
}

func Check_allowN(domain string) bool {
	root_domain:=""
	parts := strings.Split(domain, ".")
    if len(parts) <= 1 {
        return false
    }else{
		root_domain=strings.Join(parts[1:], ".")
	}
	
	val,ok:=domain_allow_one[root_domain]
	return ok && val
}