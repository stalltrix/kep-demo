package logger

import (
    "log"
	"io"
	"strconv"
	"bufio"
	"fmt"
	"os"
	"time"
)

var (
	log_level int
	archive_on bool
	archive_ch chan string
	archive_path string
)

type Log_TYPE struct {
    level  int
}

func SYS_Level(level string){
	switch level {
    case "debug":
        log_level = 0
    case "info":
        log_level = 1
    case "warn":
        log_level = 2
    case "err", "error":
        log_level = 3
    default:
        log.Fatal("log_level not found")
    }
}


func SetArchive(logfile string) {
	if archive_on{
		return
	}
	archive_on=true
	archive_path=logfile
	archive_ch=make(chan string,512)
	go write_archive()
}

func SetOutput(w io.Writer){
	log.SetOutput(w)
}

func Print(v string) {
	log.Print(v)
}

func Fatal(v string) {
	log.Fatal(v)
}

func Fatalf(format string, v ...interface{}) {
	log.Fatalf(format,v...)
}

func Fatalln(v ...interface{}) {
	log.Fatalln(v...)
}

func (l *Log_TYPE) SetLevel(level string) {
    switch level {
    case "debug":
        l.level = 0
    case "info":
        l.level = 1
    case "warn":
        l.level = 2
    case "err", "error":
        l.level = 3
	case "must":
        l.level = 4
	case "archive":
        l.level = 64
    default:
        log.Fatal("set log_level not found")
    }
}

func (l *Log_TYPE) Println(v ...interface{}) {
    if l.level < log_level {
        return
    }
	if l.level==64 && archive_on{
		args := append([]interface{}{" [level=archive]"}, v...)
		archive_ch <- fmt.Sprintln(args...)
		return
	}
    args := append([]interface{}{"[level=" + strconv.Itoa(l.level) + "]"}, v...)
    log.Println(args...)
}

func (l *Log_TYPE) Printf(format string, v ...interface{}) {
	if l.level < log_level {
		return
	}
	if l.level==64 && archive_on{
		archive_ch <- fmt.Sprintf(" [level=archive] "+format,v...)
		return
	}
	log.Printf("[level=" + strconv.Itoa(l.level) + "] "+format,v...)
}

func write_archive(){
	f, err := os.OpenFile(archive_path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Println("ERR: open archive file:",err)
		f=os.Stdout
    } else {
		defer f.Close()
	}
	w := bufio.NewWriterSize(f, 4096)
	data_changed:=false
	ticker := time.NewTicker(12 * time.Second)
	defer ticker.Stop()
go func() {
    for range ticker.C {
		if data_changed{
			data_changed=false
			w.Flush()
		}
    }
	w.Flush()
	archive_on=false
}()
for{
	txt,ok:=<-archive_ch
	if !ok {
		archive_on=false
		w.Flush()
        break
    }
	if txt==""{
		continue
	}
	logstr:=time.Now().Format("2006-01-02 15:04:05") + txt
	_, err = w.WriteString(logstr)
    if err != nil {
        log.Println("write archive log err:",err)
    } else {
		data_changed=true
	}
}
}