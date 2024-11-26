package pkg

import (
	"fmt"
	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/xuri/excelize/v2"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

type Rule struct {
	Title       string   `yaml:"title"`
	Group       string   `yaml:"group"`
	Description string   `yaml:"description"`
	Authors     []string `yaml:"authors"`

	Kind      string `yaml:"kind"`
	Level     string `yaml:"level"`
	Status    string `yaml:"status"`
	Timestamp string `yaml:"timestamp"`

	Fields []Field `yaml:"fields"`

	Filter map[string]interface{} `yaml:"filter"`
}
type Field struct {
	Name string `yaml:"name"`
	To   string `yaml:"to"`
}

func matchEvent(event *evtx.GoEvtxMap, filter map[string]interface{}) bool {
	// 处理条件逻辑
	if condition, ok := filter["condition"].(string); ok {
		// 按空格分割字符串
		parts := strings.Fields(condition)
		var conditions []string
		var andflag int
		var orflag int
		var notFlag int
		//  service_control_manager and (service_name or image_path)
		// tmd 还有这种情况没处理 todo
		for _, part := range parts {
			if part == "and" {
				andflag = 1
				continue
			}
			if part == "or" {
				orflag = 1
				continue
			}
			if part == "not" {
				notFlag = 1
				continue
			}
			conditions = append(conditions, part)
		}
		if andflag != 0 {
			var flag = true
			if notFlag != 0 {
				for key, cond := range conditions {
					if key != 0 {
						if !matchCondition2(event, filter, cond) {
							flag = false
						}
					} else {
						if !matchCondition(event, filter, cond) {
							flag = false
						}
					}
					if flag == false {
						return false
					}
				}
				return flag
			} else {
				for _, cond := range conditions {
					if !matchCondition(event, filter, cond) {
						return false
					}
				}
				return true
			}
		} else if orflag != 0 {
			for _, cond := range conditions {
				if matchCondition(event, filter, cond) {
					return true
				}
			}
			return false
		} else {
			for _, cond := range conditions {
				if !matchCondition(event, filter, cond) {
					return false
				}
			}
			return true
		}
	} else {
		// 处理如果不存在condition，则直接进行匹配！
		for key, value := range filter {
			if !MatchKeyPro(event, key, value, false) {
				return false
			}
		}
		return true
	}
}

func matchCondition(event *evtx.GoEvtxMap, filter map[string]interface{}, condition string) bool {
	condFilter, ok := filter[condition].(map[string]interface{})
	if !ok {
		return false
	}
	for key, value := range condFilter {
		if !MatchKeyPro(event, key, value, false) {
			return false
		}
	}
	return true
}

func matchCondition2(event *evtx.GoEvtxMap, filter map[string]interface{}, condition string) bool {
	condFilter, ok := filter[condition].(map[string]interface{})
	if !ok {
		test, _ := filter[condition].([]interface{})
		index := len(test)
		for i := 0; i < index; i++ {
			condFilter, ok = test[i].(map[string]interface{})
			for key, value := range condFilter {
				if !MatchKeyPro(event, key, value, true) {
					return false
				}
			}
		}
		return true
	}
	for key, value := range condFilter {
		if !MatchKeyPro(event, key, value, true) {
			return false
		}
	}
	return true
}

// ConvertPath 将点分隔的路径转换为斜杠分隔的路径
func ConvertPath(dottedPath string) string {
	return strings.ReplaceAll(dottedPath, ".", "/")
}
func MatchKeyPro(event *evtx.GoEvtxMap, key string, value interface{}, isNot bool) bool {

	slashPath := ConvertPath(key)
	parts := strings.Split(key, ".")
	var current interface{}
	// 初始化 current 为 event
	// 如果有需要获取 data[0] data[1] 需要处理 todo
	var status int
	for _, part := range parts {
		switch part {
		case "System":
			status = 1
		case "EventData":
			status = 2
		case "UserData":
			status = 3
		default:
			if status == 2 {
				var match string
				if strings.Contains(part, "Data") {
					re := regexp.MustCompile(`\d+`)
					match = re.FindString(part)
				}
				if match == "" {

				}
				path := evtx.Path(slashPath)
				desValue, _ := event.GetString(&path)
				if desValue != "" {
					current = desValue
					break
				}

			} else if status == 1 {
				path2 := evtx.Path(slashPath)
				if part == "Provider" {
					path2 = evtx.Path(slashPath + "/Name")
				}
				desValue, _ := event.GetString(&path2)
				if desValue != "" {
					current = desValue
					break
				}
			} else if status == 3 {
				path3 := evtx.Path(slashPath)
				desValue, _ := event.GetString(&path3)
				if desValue != "" {
					current = desValue
					break
				}
			}
		}
	}

	if isNot == false {
		return matchValue(value, current)
	}
	return matchValue2(value, current)

}
func matchValue2(value interface{}, current interface{}) bool {
	//fmt.Println(status)
	switch v := value.(type) {
	case int:
		if fmt.Sprintf("%v", current) == fmt.Sprintf("%v", v) {
			return false
		}
		return true
	case string:
		if strings.HasPrefix(v, "$*") {
			if strings.HasPrefix(fmt.Sprintf("%v", current), "$") {
				return false
			}
			return true
		}
		if fmt.Sprintf("%v", current) == v {
			return false
		}
		return true
	case []interface{}:
		for _, val := range v {
			if fmt.Sprintf("%v", current) == fmt.Sprintf("%v", val) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
func matchValue(value interface{}, current interface{}) bool {
	//fmt.Println(status)
	switch v := value.(type) {
	case int:
		return fmt.Sprintf("%v", current) == fmt.Sprintf("%v", v)
	case string:
		if strings.HasPrefix(v, "$*") {
			return strings.HasPrefix(fmt.Sprintf("%v", current), "$")
		}
		return fmt.Sprintf("%v", current) == v
	case []interface{}:
		for _, val := range v {
			if fmt.Sprintf("%v", current) == fmt.Sprintf("%v", val) {
				return true
			}
		}
		return false
	default:
		return false
	}
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
func MatchAllSecurityRules(event *evtx.GoEvtxMap, SecurityRuleNames []string) Rule {

	for _, ruleName := range SecurityRuleNames {
		yamlFile := GetRuleContent(ruleName)
		// 解析 YAML 文件
		var rule Rule
		if err := yaml.Unmarshal(yamlFile, &rule); err != nil {
			log.Fatalf("解析 YAML 文件时出错: %v", err)
		}

		//rule.Filter = filterRules(rule.Filter)
		if matchEvent(event, rule.Filter) {
			return rule
		}
	}
	return Rule{}

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

// WriteToExcel 将 matchedEvents 数组的值写入到 Excel 文件中
func WriteToExcel(matchedEvents []*evtx.GoEvtxMap, filePath string, rules []Rule) error {
	f := excelize.NewFile()

	// 创建一个工作表
	index, _ := f.NewSheet("Sheet1")
	headers := parseHeader(rules)

	// 设置表头
	for i, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellValue("Sheet1", cell, header)
	}

	// 写入数据
	for i, event := range matchedEvents {
		row := i + 2 // 从第二行开始写入数据

		for j, name := range headers {
			//key := fieldMap[strings.ToLower(name)]
			var key string
			for _, rule := range rules[i].Fields {
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

			value, err := event.GetString(&path)
			if err != nil {
				return fmt.Errorf("failed to get value for path %s: %w", slashPath, err)
			}
			cell, _ := excelize.CoordinatesToCellName(j+1, row)
			f.SetCellValue("Sheet1", cell, value)
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
