package main

import (
	"WinLogParser/pkg"
	"fmt"
	"time"
)

func main() {
	// 记录开始时间
	startTime := time.Now()
	pkg.ReadLog()
	endTime := time.Now()

	// 计算运行时间
	elapsedTime := endTime.Sub(startTime)

	// 打印运行时间
	fmt.Printf("WinLogParser程序运行时间: %s\n", elapsedTime)
}
