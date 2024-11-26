package src

import (
	"fmt"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/sys/windows/registry"
	"log"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

func openEventLog(uncServerName *uint16, sourceName *uint16) (handle syscall.Handle, err error) {
	r0, _, e1 := syscall.Syscall(procOpenEventLog.Addr(), 2, uintptr(unsafe.Pointer(uncServerName)), uintptr(unsafe.Pointer(sourceName)), 0)
	handle = syscall.Handle(r0)
	if handle == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func getNumberOfEventLogRecords(eventLog syscall.Handle, numberOfRecords *uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procGetNumberOfEventLogRecords.Addr(), 2, uintptr(eventLog), uintptr(unsafe.Pointer(numberOfRecords)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func closeEventLog(eventLog syscall.Handle) (err error) {
	r1, _, e1 := syscall.Syscall(procCloseEventLog.Addr(), 1, uintptr(eventLog), 0, 0)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func readEventLog(eventLog syscall.Handle, readFlags uint32, recordOffset uint32, buffer *byte, numberOfBytesToRead uint32, bytesRead *uint32, minNumberOfBytesNeeded *uint32) (err error) {
	r1, _, e1 := syscall.Syscall9(procReadEventLog.Addr(), 7, uintptr(eventLog), uintptr(readFlags), uintptr(recordOffset), uintptr(unsafe.Pointer(buffer)), uintptr(numberOfBytesToRead), uintptr(unsafe.Pointer(bytesRead)), uintptr(unsafe.Pointer(minNumberOfBytesNeeded)), 0, 0)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func getOldestEventLogRecord(eventLog syscall.Handle, oldestRecord *uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procGetOldestEventLogRecord.Addr(), 2, uintptr(eventLog), uintptr(unsafe.Pointer(oldestRecord)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func loadLibraryEx(filename *uint16, file syscall.Handle, flags uint32) (handle syscall.Handle, err error) {
	r0, _, e1 := syscall.Syscall(procLoadLibraryExW.Addr(), 3, uintptr(unsafe.Pointer(filename)), uintptr(file), uintptr(flags))
	handle = syscall.Handle(r0)
	if handle == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func formatMessage(flags uint32, source syscall.Handle, messageID uint32, languageID uint32, buffer *byte, bufferSize uint32, arguments uintptr) (numChars uint32, err error) {
	r0, _, e1 := syscall.Syscall9(procFormatMessageW.Addr(), 7, uintptr(flags), uintptr(source), uintptr(messageID), uintptr(languageID), uintptr(unsafe.Pointer(buffer)), uintptr(bufferSize), uintptr(arguments), 0, 0)
	numChars = uint32(r0)
	if numChars == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func (el *EventLog) checkData(info2 *rInfos) {

}

func (el *EventLog) output() {
	if len(el.success) > 0 {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"id", "Time", "Source Ip", "Source Port", "Account Name", "Logon Process"})
		for _, s := range el.success {
			//fmt.Println(fmt.Sprintf("time:%v,sip:%v,sport:%v,loginName:%v,loginprocess:%v",s.time,s.sip,s.sport,s.lName,s.lPro))
			table.Append([]string{"4624", s.time, s.sip, s.sport, s.lName, s.lPro})
		}
		table.Render()
	}
	if len(el.fail) > 0 {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Id", "Time", "Source Ip", "Source Port", "Account Name", "Logon Process", "Failure Reason"})
		for _, s := range el.fail {
			//fmt.Println(fmt.Sprintf("time:%v,sip:%v,sport:%v,loginName:%v,loginprocess:%v,Reasons for failure%v",s.time,s.sip,s.sport,s.lName,s.lPro,s.failinfo))
			table.Append([]string{"4625", s.time, s.sip, s.sport, s.lName, s.lPro, s.failinfo})
		}
		table.Render()
	}
}

// 搜索日志
func (el *EventLog) run(logName string) {
	// 获取statefile
	recordNumber := uint32(0)

	ptr := syscall.StringToUTF16Ptr(logName)
	// 打开日志
	h, err := openEventLog(nil, ptr)
	if err != nil {
		fmt.Println("系统权限可能不够!Administrator privileges are required!")
		return
	}
	// 关闭日志
	defer closeEventLog(h)

	var num, oldnum uint32

	// 获取日志数量
	getNumberOfEventLogRecords(h, &num)
	if err != nil {
		fmt.Println("系统权限可能不够!Administrator privileges are required!")
		return
	}

	getOldestEventLogRecord(h, &oldnum)
	if err != nil {
		fmt.Println("系统权限可能不够!Administrator privileges are required!")
		return
	}

	// 比较日志数量
	if oldnum <= recordNumber {
		if recordNumber == oldnum+num-1 {
			return
		}
		recordNumber++
	} else {
		recordNumber = oldnum
	}

	size := uint32(1)
	buf := []byte{0}

	var readBytes uint32
	var nextSize uint32

	// 循环读取日志
loop_events:
	for i := recordNumber; i < oldnum+num; i++ {
		flags := EVENTLOG_FORWARDS_READ | EVENTLOG_SEEK_READ
		if i == 0 {
			flags = EVENTLOG_FORWARDS_READ | EVENTLOG_SEQUENTIAL_READ
		}
		err = readEventLog(
			h,
			uint32(flags),
			i,
			&buf[0],
			size,
			&readBytes,
			&nextSize)
		if err != nil {
			if err != syscall.ERROR_INSUFFICIENT_BUFFER {
				if err != errorInvalidParameter {
					return
				}
				break
			}
			buf = make([]byte, nextSize)
			size = nextSize
			err = readEventLog(
				h,
				uint32(flags),
				i,
				&buf[0],
				size,
				&readBytes,
				&nextSize)
			if err != nil {
				log.Printf("eventlog.ReadEventLog: %v", err)
				break
			}
		}
		r := *(*EVENTLOGRECORD)(unsafe.Pointer(&buf[0]))
		// 4624
		if r.EventID == 4624 {
			si := SuccessInfo{}
			si.time = time.Unix(int64(r.TimeGenerated), 0).String()
			// even code takes last 4 byte
			eventID := r.EventID & 0x0000FFFF
			if len(el.eventID) > 0 {
				accepted := false
				for _, idr := range el.eventID {
					if idr.lo <= eventID && eventID <= idr.hi {
						accepted = true
						break
					}
				}
				if !accepted {
					continue loop_events
				}
			}

			// 获取字段
			sourceName, _ := bytesToString(buf[unsafe.Sizeof(EVENTLOGRECORD{}):])
			off := uint32(0)
			args := make([]*byte, uintptr(r.NumStrings)*unsafe.Sizeof((*uint16)(nil)))
			for n := 0; n < int(r.NumStrings); n++ {
				args[n] = &buf[r.StringOffset+off]
				_, boff := bytesToString(buf[r.StringOffset+off:])
				off += boff + 2
			}
			var argsptr uintptr
			if r.NumStrings > 0 {
				argsptr = uintptr(unsafe.Pointer(&args[0]))
			}
			// 信息, 帐户登录失败。 已成功登录帐户。
			message, _ := getResourceMessage(logName, sourceName, r.EventID, argsptr)
			//fmt.Println(message)
			//log.Printf("Message=%v", message)
			if srcIp := getSrcIP(message); srcIp != "" {
				//fmt.Println("sip:",srcIp)
				si.sip = srcIp
				if srcPort := getSrcPort(message); srcPort != "" {
					//fmt.Println("srcPort:",srcPort)
					si.sport = srcPort
				}
				if ln := getSucLoginName(message); len(ln) != 0 {
					//fmt.Println("loginName:",ln)
					si.lName = ln
				}
				if lp := getLoginPro(message); lp != "" {
					//fmt.Println("loginProccess:",lp)
					si.lPro = lp
				}
				el.success = append(el.success, si)
			}
		}
		if r.EventID == 4625 {
			//fmt.Println("TimeGenerated:", time.Unix(int64(r.TimeGenerated), 0).String())
			fi := FailInfo{}
			fi.time = time.Unix(int64(r.TimeGenerated), 0).String()
			eventID := r.EventID & 0x0000FFFF
			if len(el.eventID) > 0 {
				accepted := false
				for _, idr := range el.eventID {
					if idr.lo <= eventID && eventID <= idr.hi {
						accepted = true
						break
					}
				}
				if !accepted {
					continue loop_events
				}
			}

			// 获取字段
			sourceName, _ := bytesToString(buf[unsafe.Sizeof(EVENTLOGRECORD{}):])
			off := uint32(0)
			args := make([]*byte, uintptr(r.NumStrings)*unsafe.Sizeof((*uint16)(nil)))
			for n := 0; n < int(r.NumStrings); n++ {
				args[n] = &buf[r.StringOffset+off]
				_, boff := bytesToString(buf[r.StringOffset+off:])
				off += boff + 2
			}

			var argsptr uintptr
			if r.NumStrings > 0 {
				argsptr = uintptr(unsafe.Pointer(&args[0]))
			}
			// 信息, 帐户登录失败。 已成功登录帐户。
			message, _ := getResourceMessage(logName, sourceName, r.EventID, argsptr)
			//fmt.Println(message)
			//log.Printf("Message=%v", message)
			if srcIp := getSrcIP(message); srcIp != "" {
				//fmt.Println("sip:",srcIp)
				fi.sip = srcIp
				if srcPort := getSrcPort(message); srcPort != "" {
					//fmt.Println("srcPort:",srcPort)
					fi.sport = srcPort
				}
				if failm := getFail(message); failm != "" {
					//fmt.Println("failMessage:",failm)
					fi.failinfo = failm
				}
				if ln := getFailLoginName(message); len(ln) != 0 {
					//fmt.Println("loginName:",ln)
					fi.lName = ln
				}
				if lp := getLoginPro(message); lp != "" {
					//fmt.Println("loginProccess:",lp)
					fi.lPro = lp
				}
				el.fail = append(el.fail, fi)
			}
		}
	}
}
func bytesToString(b []byte) (string, uint32) {
	var i int
	s := make([]uint16, len(b)/2)
	for i = range s {
		s[i] = uint16(b[i*2]) + uint16(b[(i*2)+1])<<8
		if s[i] == 0 {
			s = s[0:i]
			break
		}
	}
	return string(utf16.Decode(s)), uint32(i * 2)
}

func getResourceMessage(providerName, sourceName string, eventID uint32, argsptr uintptr) (string, error) {
	regkey := fmt.Sprintf(
		"SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s\\%s",
		providerName, sourceName)
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, regkey, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer key.Close()

	val, _, err := key.GetStringValue("EventMessageFile")
	if err != nil {
		return "", err
	}
	val, err = registry.ExpandString(val)
	if err != nil {
		return "", err
	}

	handle, err := loadLibraryEx(syscall.StringToUTF16Ptr(val), 0,
		DONT_RESOLVE_DLL_REFERENCES|LOAD_LIBRARY_AS_DATAFILE)
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(handle)

	msgbuf := make([]byte, 1<<16)
	numChars, err := formatMessage(
		syscall.FORMAT_MESSAGE_FROM_SYSTEM|
			syscall.FORMAT_MESSAGE_FROM_HMODULE|
			syscall.FORMAT_MESSAGE_ARGUMENT_ARRAY,
		handle,
		eventID,
		0,
		&msgbuf[0],
		uint32(len(msgbuf)),
		argsptr)
	if err != nil {
		return "", err
	}
	message, _ := bytesToString(msgbuf[:numChars*2])
	message = strings.Replace(message, "\r", "", -1)
	message = strings.TrimSuffix(message, "\n")
	return message, nil
}

func getFail(message string) string {
	// 失败原因:	%%2313
	reg := regexp.MustCompile(`失败原因:[\t\n\f\r]+(.*)`)
	result := reg.FindAllStringSubmatch(message, -1)
	if len(result) > 0 {
		return result[0][1]
	} else {
		return ""
	}
}
func getSrcIP(message string) string {
	// 源网络地址:	192.168.43.251
	reg := regexp.MustCompile(`源网络地址:[\t\n\f\r]+(.*)`)
	result := reg.FindAllStringSubmatch(message, -1)
	if len(result) > 0 {
		sip := result[0][1]
		if strings.Contains(sip, "-") {
			return ""
		}
		return result[0][1]
	} else {
		return ""
	}
}

func getSrcPort(message string) string {
	// 源端口:		0
	reg := regexp.MustCompile(`源端口:[\t\n\f\r]+(.*)`)
	result := reg.FindAllStringSubmatch(message, -1)
	if len(result) > 0 {
		return result[0][1]
	} else {
		return ""
	}
}

// 失败 帐户名
func getFailLoginName(message string) string {
	// 帐户名:		2
	reg := regexp.MustCompile(`帐户名:[\t\n\f\r]+(.*)`)
	result := reg.FindAllStringSubmatch(message, -1)
	if len(result) > 0 {
		return result[1][1]
	} else {
		return ""
	}
}

// 成功 帐户名称
func getSucLoginName(message string) string {
	// 帐户名称:		2
	reg := regexp.MustCompile(`帐户名称:[\t\n\f\r]+(.*)`)
	result := reg.FindAllStringSubmatch(message, -1)
	if len(result) > 0 {
		return result[1][1]
	} else {
		return ""
	}
}
func getLoginPro(message string) string {
	// 登录进程:	NtLmSsp
	reg := regexp.MustCompile(`登录进程:[\t\n\f\r]+(.*)`)
	result := reg.FindAllStringSubmatch(message, -1)
	if len(result) > 0 {
		return result[0][1]
	} else {
		return ""
	}
}
