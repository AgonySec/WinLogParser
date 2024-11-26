package rules

import (
	"embed"
	"fmt"
	"io/fs"
)

//go:embed test/*
var contentFS embed.FS

func GetSecurityRuleNames() (SecurityRules []string) {
	// 通过 ReadDir 读取目录中 的文件
	files, err := fs.ReadDir(contentFS, "test")
	if err != nil {
		fmt.Println("Error reading directory:", err)
		return
	}
	// 遍历文件并将内容保存到数组中
	for _, file := range files {
		//fmt.Println(file.Name())
		SecurityRules = append(SecurityRules, file.Name())
	}
	//loaderNames = append(loaderNames, "all.txt")
	return SecurityRules
}
func GetSecurityRuleContent(securityRuleName string) (SecurityRuleContent []byte) {
	//通过 ReadFile 读取文件内容
	fileData, _ := fs.ReadFile(contentFS, "test/"+securityRuleName)
	// 将文件内容转换为字符串并添加到数组
	//securityRuleName = string(fileData)
	//fmt.Println(loaderContent)
	return fileData
}
