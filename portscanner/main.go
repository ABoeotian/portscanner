package main

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// 端口和服务的映射
var portServices = map[int]string{
	21:   "FTP - 文件传输协议",
	22:   "SSH - 安全外壳协议",
	23:   "Telnet - 明文传输协议",
	25:   "SMTP - 简单邮件传输协议",
	53:   "DNS - 域名系统",
	80:   "HTTP - 超文本传输协议",
	443:  "HTTPS - 安全超文本传输协议",
	8080: "HTTP 代理端口",
	3306: "MySQL - 数据库服务",
	3389: "RDP - 远程桌面协议",
	5900: "VNC - 虚拟网络计算",
}

// 常见的服务漏洞映射
var serviceVulnerabilities = map[string][]string{
	"FTP - 文件传输协议": {
		"未加密的传输可能导致明文传输敏感信息。",
		"FTP 服务的默认弱口令。",
	},
	"SSH - 安全外壳协议": {
		"弱密码攻击。",
		"暴力破解攻击。",
	},
	"Telnet - 明文传输协议": {
		"数据以明文传输，容易被中间人攻击（MITM）。",
		"默认用户名和密码较弱。",
	},
	"SMTP - 简单邮件传输协议": {
		"开放邮件中继可能导致垃圾邮件发送。",
	},
	"DNS - 域名系统": {
		"DNS 伪造攻击。",
		"缓存投毒攻击。",
	},
	"HTTP - 超文本传输协议": {
		"SQL 注入攻击。",
		"跨站脚本（XSS）攻击。",
	},
	"HTTPS - 安全超文本传输协议": {
		"SSL/TLS 配置不当导致中间人攻击。",
		"弱加密算法攻击。",
	},
	"MySQL - 数据库服务": {
		"SQL 注入攻击。",
		"弱密码或默认账号登录。",
	},
	"RDP - 远程桌面协议": {
		"暴力破解攻击。",
		"远程桌面服务配置不当导致的未授权访问。",
	},
	"VNC - 虚拟网络计算": {
		"暴力破解攻击。",
		"默认密码可能导致未授权访问。",
	},
}

func main() {
	// 创建 Fyne 应用
	myApp := app.New()
	myWindow := myApp.NewWindow("端口扫描工具")

	// UI 组件
	targetEntry := widget.NewEntry()
	targetEntry.SetPlaceHolder("请输入目标主机 IP 或域名")

	startPortEntry := widget.NewEntry()
	startPortEntry.SetPlaceHolder("请输入扫描端口的起始端口")

	endPortEntry := widget.NewEntry()
	endPortEntry.SetPlaceHolder("请输入扫描端口的结束端口")

	resultLabel := widget.NewLabel("扫描结果将显示在此处")

	// 扫描端口的按钮
	scanButton := widget.NewButtonWithIcon("开始扫描", theme.ContentAddIcon(), func() {
		// 获取用户输入
		target := targetEntry.Text
		startPort, err1 := strconv.Atoi(startPortEntry.Text)
		endPort, err2 := strconv.Atoi(endPortEntry.Text)

		if err1 != nil || err2 != nil {
			resultLabel.SetText("请检查输入的端口范围是否正确！")
			return
		}

		// 清空扫描结果
		resultLabel.SetText("扫描中，请稍等...")

		// 开始并发扫描
		var result string
		resultChan := make(chan string, endPort-startPort+1)

		for port := startPort; port <= endPort; port++ {
			go func(port int) {
				resultChan <- scanPort(target, port)
			}(port)
		}

		// 等待所有扫描结果
		for port := startPort; port <= endPort; port++ {
			result += <-resultChan
		}
		// 显示扫描结果
		resultLabel.SetText(result)
	})

	// 布局
	myWindow.SetContent(container.NewVBox(
		widget.NewLabel("目标主机："),
		targetEntry,
		widget.NewLabel("起始端口："),
		startPortEntry,
		widget.NewLabel("结束端口："),
		endPortEntry,
		scanButton,
		resultLabel,
	))

	// 设置窗口大小
	myWindow.Resize(fyne.NewSize(400, 300))

	// 运行应用
	myWindow.ShowAndRun()
}

// 扫描端口函数
func scanPort(target string, port int) string {
	// 设置连接超时
	timeout := time.Second * 2

	// 拼接目标主机和端口
	address := fmt.Sprintf("%s:%d", target, port)

	// 尝试连接
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		// 如果有错误，说明端口关闭
		return ""
	}
	defer conn.Close()

	// 如果没有错误，说明端口开放
	service, found := portServices[port]
	if found {
		// 输出开放端口及其对应服务信息
		result := fmt.Sprintf("端口 %d 开放 - 服务: %s\n", port, service)
		if vulnerabilities, ok := serviceVulnerabilities[service]; ok {
			result += "可能存在的漏洞:\n"
			for _, vuln := range vulnerabilities {
				result += fmt.Sprintf("  - %s\n", vuln)
			}
		} else {
			result += "没有已知的漏洞信息。\n"
		}
		return result
	} else {
		// 如果没有找到该端口的服务信息
		return fmt.Sprintf("端口 %d 开放 - 服务信息未知\n", port)
	}
}
