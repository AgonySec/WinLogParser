package pkg

import (
	"fmt"
	"github.com/0xrawsec/golang-evtx/evtx"
	"gopkg.in/yaml.v3"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"
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

// service_control_manager and (service_name or image_path)
func matchCon(event *evtx.GoEvtxMap, filter map[string]interface{}, condition string) bool {
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
}
func matchEvent2(event *evtx.GoEvtxMap, filter map[string]interface{}) bool {
	if condition, ok := filter["condition"].(string); ok {
		if strings.Contains(condition, "(") {
			cond := strings.Fields(condition)
			if !matchCondition(event, filter, cond[0]) {
				return false
			}
			pattern := `\((.*?)\)`
			re := regexp.MustCompile(pattern)
			matches := re.FindStringSubmatch(condition)
			return matchCon(event, filter, matches[1])
		} else {
			return matchCon(event, filter, condition)
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

func MatchKeyPro(event *evtx.GoEvtxMap, key string, value interface{}, isNot bool) bool {

	slashPath := ConvertPath(key)
	parts := strings.Split(key, ".")
	var current interface{}
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
				if match != "" {
					path := evtx.Path("/Event/EventData/Data")

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
									current = j
								}
							}
						}
					}
					break
				}
				path := evtx.Path(slashPath)
				desValue, _ := event.GetString(&path)
				current = desValue

			} else if status == 1 {
				path2 := evtx.Path(slashPath)
				if part == "Provider" {
					path2 = evtx.Path(slashPath + "/Name")
				}

				desValue, _ := event.GetString(&path2)
				// 如果eventID为空，则尝试获取 /eventID/Value
				if desValue == "" {
					path2 = evtx.Path(slashPath + "/Value")
					desValue, _ = event.GetString(&path2)
				}

				if desValue != "" {
					current = desValue
					break
				}
			} else if status == 3 {
				path3 := evtx.Path(slashPath)
				desValue, _ := event.GetString(&path3)
				if desValue != "" {
					current = desValue
				} else {
					current = ""
				}
			}
		}
	}
	if value == nil {
		value = ""
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
		if fmt.Sprintf("%v", v) == "" && fmt.Sprintf("%v", current) == "" {
			return false
		}
		return fmt.Sprintf("%v", current) == v
	case []interface{}:
		for _, val := range v {
			if strings.HasPrefix(fmt.Sprintf("%v", val), "i") {
				if MatchPattern(fmt.Sprintf("%v", val), fmt.Sprintf("%v", current)) {
					return true
				}
			} else if fmt.Sprintf("%v", current) == fmt.Sprintf("%v", val) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// MatchPattern 检查给定的字符串是否匹配任何一个规则
func MatchPattern(pattern string, input string) bool {

	// 将模式和输入字符串转换为小写进行不区分大小写的匹配
	lowerPattern := strings.ToLower(pattern)
	lowerInput := strings.ToLower(input)

	// 去掉模式中的 "i*" 前缀
	if strings.HasPrefix(lowerPattern, "i*") {
		cleanPattern := strings.TrimPrefix(lowerPattern, "i*")
		// 去掉所有的 "*"
		cleanPattern = strings.ReplaceAll(cleanPattern, "*", "")
		if strings.Contains(lowerInput, cleanPattern) {
			return true
		}
	} else if strings.HasPrefix(lowerPattern, "i?") {
		// 判断是否是正则表达式模式
		// 去掉前缀 "i?"
		cleanPattern := lowerPattern[2:]
		// 编译正则表达式
		re, _ := regexp.Compile(cleanPattern)

		// 使用正则表达式进行匹配
		if re.MatchString(lowerInput) {
			return true
		}
	} else {

	}
	return false
}

var ruleCache = make(map[string]Rule)
var cacheLock sync.Mutex

// 获取规则内容并缓存，做了这个处理之后，tm的运行时间从3m14 直接降到2s左右
func GetCachedRuleContent(ruleName string) Rule {
	cacheLock.Lock()
	defer cacheLock.Unlock()

	if rule, ok := ruleCache[ruleName]; ok {
		return rule
	}

	yamlFile := GetRuleContent(ruleName)
	var rule Rule
	if err := yaml.Unmarshal(yamlFile, &rule); err != nil {
		log.Fatalf("解析 YAML 文件时出错: %v", err)
	}
	ruleCache[ruleName] = rule
	return rule
}

func MatchAllSecurityRules(event *evtx.GoEvtxMap, SecurityRuleNames []string) Rule {
	for _, ruleName := range SecurityRuleNames {
		rule := GetCachedRuleContent(ruleName)
		// 如果事件匹配规则，立即返回
		if matchEvent2(event, rule.Filter) {
			return rule
		}
	}
	return Rule{}
}
