package pkg

import (
	"fmt"
	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/xuri/excelize/v2"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func DisplayBanner() {
	fmt.Println(" _       ___       __                ____                           ")
	fmt.Println("| |     / (_)___  / /   ____  ____ _/ __ \\____ ______________  _____")
	fmt.Println("| | /| / / / __ \\/ /   / __ \\/ __ `/ /_/ / __ `/ ___/ ___/ _ \\/ ___/")
	fmt.Println("| |/ |/ / / / / / /___/ /_/ / /_/ / ____/ /_/ / /  (__  )  __/ /    ")
	fmt.Println("|__/|__/_/_/ /_/_____/\\____/\\__, /_/    \\__,_/_/  /____/\\___/_/     ")
	fmt.Println("                           /____/                                   ")
	fmt.Println("欢迎使用 WinLogParser 一款Windows日志自动分析工具 by:Agony")
	fmt.Println("=====================================================================")
}

// ConvertPath 将点分隔的路径转换为斜杠分隔的路径
func ConvertPath(dottedPath string) string {
	return strings.ReplaceAll(dottedPath, ".", "/")
}
func GetRuleContent(ruleFilePath string) []byte {
	// 打开文件
	file, err := os.Open(ruleFilePath)
	if err != nil {
		log.Printf("打开文件时出错: %v", err)
		return nil
	}
	defer file.Close()

	// 读取文件内容
	content, err := ioutil.ReadAll(file)
	if err != nil {
		log.Printf("读取文件内容时出错: %v", err)

	}
	return content

}
func WriteToExcel2(eventResult EventResult, filePath string) error {
	f := excelize.NewFile()
	// 创建一个工作表
	index, _ := f.NewSheet("Sheet1")
	headers := parseHeader(eventResult.rules)
	headers = append(headers, "timestamp")
	headers = append(headers, "detections")
	headers = append(headers, "path")

	//log.Printf("Headers: %v", headers)
	// 设置表头
	for i, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellValue("Sheet1", cell, header)
	}

	// 写入数据
	for i, event := range eventResult.matchedEvents {
		row := i + 2 // 从第二行开始写入数据

		for j, name := range headers {
			var key string
			if name == "detections" {
				value := eventResult.rules[i].Title
				cell, _ := excelize.CoordinatesToCellName(j+1, row)
				f.SetCellValue("Sheet1", cell, value)

			} else if name == "timestamp" {
				value := event.TimeCreated()
				// 将 evtx.UTCTime 转换为 string
				timestampStr := value.Format(time.RFC3339)
				cell, _ := excelize.CoordinatesToCellName(j+1, row)
				f.SetCellValue("Sheet1", cell, timestampStr)
			} else if name == "path" {
				value := eventResult.evtxFileName[i]
				cell, _ := excelize.CoordinatesToCellName(j+1, row)
				f.SetCellValue("Sheet1", cell, value)
			} else {
				for _, rule := range eventResult.rules[i].Fields {
					if rule.Name == name {
						key = rule.To
						break
					}
				}
				slashPath := ConvertPath(key)
				path := evtx.Path(slashPath)
				if strings.Contains(slashPath, "Provider") {
					path = evtx.Path(slashPath + "/Name")
				}
				var value string
				if key == "" {
					value = ""
				} else {
					value, _ = event.GetString(&path)
				}
				if event.EventID() == int64(15457) {
					if name == "Event ID" {
						slashPath = ConvertPath(key)
						path = evtx.Path(slashPath + "/Value")
						value, _ = event.GetString(&path)
					}
					if name == "Command" {
						path = evtx.Path("/Event/EventData/Data")
						eventMap2 := event.GetMapStrict(&path)
						if eventMap2 != nil {
							// 解引用指针并进行类型断言
							normalMap := map[string]interface{}(*eventMap2)
							// 获取 Data 值
							dataValue, _ := normalMap["Data"]

							// 将 dataValue 转换为 []string 类型
							dataSlice, ok := dataValue.([]string)
							if ok {
								// 将 dataSlice 转换为一个 string 类型对象
								value = strings.Join(dataSlice, "\n")
							}
						}
					}
					if name == "Username" {
						value = "MSSQLSERVER"
					}
					if strings.Contains(key, "Data") {
						re := regexp.MustCompile(`\d+`)
						match := re.FindString(key)
						path = evtx.Path("/Event/EventData/Data")
						eventMap2, _ := event.GetMap(&path)
						if eventMap2 != nil {
							// 解引用指针并进行类型断言
							normalMap := map[string]interface{}(*eventMap2)
							// 获取 Data 值
							dataValue, _ := normalMap["Data"]

							// 将 dataValue 转换为 []string 类型
							dataSlice, ok := dataValue.([]string)
							if ok {
								for i, j := range dataSlice {
									if strconv.Itoa(i) == match {
										value = j
									}
								}
							}
						}
					}
				}
				if event.EventID() == int64(400) || event.EventID() == int64(403) {
					if name == "Event ID" {
						slashPath = ConvertPath(key)
						path = evtx.Path(slashPath + "/Value")
						value, _ = event.GetString(&path)
					}
					if value == "" {
						re := regexp.MustCompile(`\d+`)
						key = "Event.EventData.Data[2]"
						match := re.FindString(key)
						path = evtx.Path("/Event/EventData/Data")
						eventMap2, _ := event.GetMap(&path)
						if eventMap2 != nil {
							// 解引用指针并进行类型断言
							normalMap := map[string]interface{}(*eventMap2)
							// 获取 Data 值
							dataValue, _ := normalMap["Data"]

							// 将 dataValue 转换为 []string 类型
							dataSlice, ok := dataValue.([]string)
							if ok {
								for m, dataValues := range dataSlice {
									if strconv.Itoa(m) == match {
										value = getKeyValue(dataValues, name)
									}
								}
							}
						}
					}
				}
				if name == "Event ID" && value == "" {
					slashPath = ConvertPath(key)
					path = evtx.Path(slashPath + "/Value")
					value, _ = event.GetString(&path)
				}
				cell, _ := excelize.CoordinatesToCellName(j+1, row)
				f.SetCellValue("Sheet1", cell, value)
			}

		}
	}

	// 设置活动工作表
	f.SetActiveSheet(index)

	// 保存文件
	if err := f.SaveAs(filePath); err != nil {
		return err
	}

	return nil
}
func getKeyValue(data, keys string) string {
	// 将文本按行分割
	lines := strings.Split(data, "\n")

	// 遍历每一行，查找HostName的值
	for _, line := range lines {
		// 去除行首和行尾的空白字符
		line = strings.TrimSpace(line)
		// 检查行是否包含等号，即键值对
		if strings.Contains(line, "=") {
			// 分割键和值
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				// 检查键是否为HostName
				if key == keys {
					return value
				}
			}
		}
	}
	return ""
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
