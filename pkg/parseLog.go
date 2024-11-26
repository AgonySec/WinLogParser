package pkg

import (
	"fmt"
	"github.com/0xrawsec/golang-evtx/evtx"
	"log"
	"os"
	"path/filepath"
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

type EventResult struct {
	matchedEvents []*evtx.GoEvtxMap
	rules         []Rule
	evtxFileName  []string
}

func ReadLog() {
	evxtDir := "C:\\Users\\chenyuanhang\\Downloads\\Testingggggg\\chainsaw\\EVTX-ATTACK-SAMPLES\\Command and Control"
	// 读取指定目录下的所有 .evtx 文件
	evtxFiles, err := readEVTXFiles(evxtDir)
	if err != nil {
		fmt.Printf("Error reading EVTX files: %v\n", err)
		return
	}
	// 初始化结果映射
	rulesResult := make(map[string][]string)
	rulesDir := "C:\\Users\\chenyuanhang\\Documents\\WorkSpace\\WinLogParser\\rules\\rdp_attacks"

	// 读取指定目录下的所有 .yml 文件
	err = readYMLFiles(rulesDir, rulesResult)
	if err != nil {
		fmt.Printf("Error reading YML files: %v\n", err)
		return
	}
	// 打印结果
	for dirName, ymlFiles := range rulesResult {
		// 打印找到的 .evtx 文件
		var matchedEvents []*evtx.GoEvtxMap
		var rules []Rule
		var evtxFileNames []string
		var eventResult EventResult
		for _, evtxFileName := range evtxFiles {
			eventFile, err := evtx.OpenDirty(evtxFileName)
			if err != nil {
				log.Fatal(err)
			}
			for event := range eventFile.FastEvents() {
				rule := MatchAllSecurityRules(event, ymlFiles)
				if rule.Title != "" {
					matchedEvents = append(matchedEvents, event)
					rules = append(rules, rule)
					evtxFileNames = append(evtxFileNames, evtxFileName)
					//eventResult = append(eventResult, EventResult{matchedEvents: event, rules: rule, evtxFileName: evtxFileName})
				}
			}
		}
		eventResult = EventResult{matchedEvents: matchedEvents, rules: rules, evtxFileName: evtxFileNames}
		// 写入 Excel 文件
		filePath := dirName + ".xlsx"
		if err := WriteToExcel2(eventResult, filePath); err != nil {
			log.Fatalf("写入 Excel 文件时出错: %v", err)
		}
		log.Println("已写入 Excel 文件:", filePath)
	}
}
func parseHeader(rules []Rule) []string {
	var fields []Field
	var header []string
	for _, rule := range rules {
		fields = append(fields, rule.Fields...)
	}
	for _, field := range fields {
		fieldName := field.Name
		if !contains(header, fieldName) {
			header = append(header, fieldName)
		}
	}
	return header
}

// 辅助函数，检查切片中是否包含指定的字符串
func contains(slice []string, str string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}
