package pkg

import (
	"fmt"
	"github.com/0xrawsec/golang-evtx/evtx"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// 读取指定目录下所有的 .evtx 文件
func readEVTXFiles(dir string) ([]string, error) {
	var evtxFiles []string

	// 遍历目录
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".evtx" {
			evtxFiles = append(evtxFiles, path)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return evtxFiles, nil
}

// 递归遍历目录，读取所有 .yml 文件
func readYMLFiles(dir string, result map[string][]string) error {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (filepath.Ext(path) == ".yml" || filepath.Ext(path) == ".yaml") {
			// 获取文件所在目录的名称
			dirName := filepath.Base(filepath.Dir(path))
			// 将文件路径添加到结果中
			result[dirName] = append(result[dirName], path)
		}
		return nil
	})
	return err
}

// 定义 EventMatch 结构体
type EventMatch struct {
	event    *evtx.GoEvtxMap
	rule     Rule
	fileName string
}

type EventResult struct {
	matchedEvents []*evtx.GoEvtxMap
	rules         []Rule
	evtxFileName  []string
	dirName       string
}

func ReadLogPro() {
	// 获取当前程序所在的目录
	currentDir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current directory:", err)
		return
	}
	// 拼接 evtx 文件夹的路径
	evtxDir := filepath.Join(currentDir, "evtx")

	// 读取指定目录下的所有 .evtx 文件
	evtxFiles, err := readEVTXFiles(evtxDir)
	fmt.Printf("载入 %d EVTX 文件\n", len(evtxFiles))
	if err != nil {
		fmt.Printf("Error reading EVTX files: %v\n", err)
		return
	}
	// 初始化结果映射
	rulesResult := make(map[string][]string)
	rulesDir := filepath.Join(currentDir, "rules")
	// 读取指定目录下的所有 .yml 文件
	err = readYMLFiles(rulesDir, rulesResult)
	fmt.Printf("载入 %d 个规则文件夹\n", len(rulesResult))
	if err != nil {
		fmt.Printf("Error reading YML files: %v\n", err)
		return
	}
	// 创建 output 文件夹
	outputDir := filepath.Join(currentDir, "output")
	err = os.MkdirAll(outputDir, 0755)
	if err != nil {
		fmt.Printf("Error creating output directory: %v\n", err)
		return
	}
	var eventsMap = make(map[string][]*evtx.GoEvtxMap)

	for _, evtxFileName := range evtxFiles {
		eventFile, err := evtx.OpenDirty(evtxFileName)
		if err != nil {
			log.Printf("Failed to open EVTX file %s: %v", evtxFileName, err)
			continue
		}
		var events []*evtx.GoEvtxMap
		for event := range eventFile.FastEvents() {
			events = append(events, event)
		}
		eventsMap[evtxFileName] = events
	}
	// 创建一个等待组，用于等待所有 goroutine 完成
	var wg sync.WaitGroup
	// 创建一个通道，用于收集结果
	resultChan := make(chan EventResult, len(evtxFiles))

	// 限制并发数量
	const maxConcurrency = 10
	sem := make(chan struct{}, maxConcurrency)

	// 启动多个 goroutine 处理每个 .evtx 文件
	for dirName, ymlFiles := range rulesResult {
		wg.Add(1)
		go func(dirName string, ymlFiles []string) {
			defer wg.Done()
			sem <- struct{}{}        // 获取一个许可
			defer func() { <-sem }() // 释放许可

			// 打印找到的 .evtx 文件
			var matchedEvents []*evtx.GoEvtxMap
			var rules []Rule
			var evtxFileNames []string
			// 遍历 eventsMap
			for evtxFileName, events := range eventsMap {
				for _, event := range events {
					rule := MatchAllSecurityRules(event, ymlFiles)
					if rule.Title != "" {
						matchedEvents = append(matchedEvents, event)
						rules = append(rules, rule)
						evtxFileNames = append(evtxFileNames, evtxFileName)
					}
				}
			}
			eventResult := EventResult{matchedEvents: matchedEvents, rules: rules, evtxFileName: evtxFileNames, dirName: dirName}
			resultChan <- eventResult
		}(dirName, ymlFiles)
	}

	// 等待所有 goroutine 完成
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 收集所有结果并写入 Excel 文件
	for eventResult := range resultChan {
		if len(eventResult.rules) != 0 {
			filePath := filepath.Join(outputDir, eventResult.dirName+".xlsx")
			if err := WriteToExcel2(eventResult, filePath); err != nil {
				log.Fatalf("写入Excel文件出现了一个bug: %v", err)
			}
			log.Println("成功写入Excel文件", filePath)
		}
	}
}
