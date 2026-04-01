package logger

import (
    "log"
	"io"
	"strconv"
)

var log_level int

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
        l.level = 64
    default:
        log.Fatal("set log_level not found")
    }
}

func (l *Log_TYPE) Println(v ...interface{}) {
    if l.level < log_level {
        return
    }
    args := append([]interface{}{"[level=" + strconv.Itoa(l.level) + "]"}, v...)
    log.Println(args...)
}

func (l *Log_TYPE) Printf(format string, v ...interface{}) {
	if l.level < log_level {
		return
	}
	log.Printf("[level=" + strconv.Itoa(l.level) + "] "+format,v...)
}