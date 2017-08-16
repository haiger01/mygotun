package mylog

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var logFile = flag.String("log.file", "", "save log file path")
var logNum = flag.Int("log.num", 20000, " the loginfo number of log file")

const (
	LOG_DEPTH = 3
	LDEBUG    = iota
	LINFO     //1
	LNOTICE
	LWARNING
	LERROR
)

var loglevel int
var MyLogInfoNum uint64 = 0
var LogInfoThreshold uint64 = 0
var logLock sync.Mutex

var lf *os.File

func redirectStderr(f *os.File) {
	err := syscall.Dup2(int(f.Fd()), int(os.Stderr.Fd()))
	if err != nil {
		log.Fatalf("Failed to redirect stderr to file: %v", err)
	}
}

func fileExist(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil || os.IsExist(err)
}

func InitLog(log_level int) {
	loglevel = log_level
	LogInfoThreshold = uint64(*logNum)
	createLogFile()
}

func Close() {
	if lf != nil {
		lf.Close()
	}
}

func init() {

}

func createLogFile() {
	logfile := *logFile
	log.Printf("=======original log.file is : %s, try to create it, logNum=%d===========\n", logfile, *logNum)
	var err error
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	if logfile != "" {
		if fileExist(logfile) {
			log.Printf("log file %s already exist\n", logfile)
			//t := time.Now().Format(layout)
			t := time.Now()
			year, month, day := t.Date()
			filename := path.Base(logfile)
			fileSuffix := path.Ext(filename) //获取文件后缀
			filename_olny := strings.TrimSuffix(filename, fileSuffix)
			logfile = path.Dir(logfile) + string(os.PathSeparator) + filename_olny +
				fmt.Sprintf("_%d-%d-%d_%d-%d-%d", year, month, day, t.Hour(), t.Minute(), t.Second()) +
				fileSuffix
			log.Printf("generate new log file name: %s\n", logfile)
		}
		os.MkdirAll(path.Dir(logfile), 0644)
		lf, err = os.OpenFile(logfile, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			log.Fatalln("open log file error: ", err)
		}

		log.Printf("create log file  %s success, now set log output to the file\n", logfile)
		redirectStderr(lf)
		log.SetOutput(lf)
	}
}

func NewLogFile() {
	logLock.Lock()
	//atomic.LoadUint64(&MyLogInfoNum)
	if MyLogInfoNum <= LogInfoThreshold {
		logLock.Unlock()
		return
	}
	LogInfoThreshold += uint64(*logNum)
	logLock.Unlock()

	createLogFile()
}

func putToLog(level int, pre string, format string, a ...interface{}) {
	if loglevel <= level {
		pre_str := fmt.Sprintf("[%s %d] ", pre, MyLogInfoNum)
		log.Output(LOG_DEPTH, fmt.Sprintf(pre_str+format, a...))
		atomic.AddUint64(&MyLogInfoNum, 1)
		if MyLogInfoNum > LogInfoThreshold {
			NewLogFile()
		}
	}
}

func Debug(format string, a ...interface{}) {
	putToLog(LDEBUG, "Debug", format, a...)
}

func Info(format string, a ...interface{}) {
	putToLog(LINFO, "Info", format, a...)
}

func Notice(format string, a ...interface{}) {
	putToLog(LNOTICE, "Notice", format, a...)
}

func Warning(format string, a ...interface{}) {
	putToLog(LWARNING, "Warning", format, a...)
}

func Error(format string, a ...interface{}) {
	putToLog(LERROR, "Error", format, a...)
}