## 使用go实现一个简单的端口扫描工具,采用了 Fyne 框架来构建GUI     
## 工具的功能是扫描指定目标主机的端口范围，并根据开放的端口识别对应的服务以及可能存在的漏洞    
> 此项目是学习 go 语言后进行的一个简单练习实现, 所以很简陋, 还请诸位大佬多指点  

## 主要功能:   
> 1. 输入目标主机的 IP 或域名，以及端口扫描的起始和结束端口，程序会并发地尝试连接每个端口，判断端口是否开放   
> 2. 根据开放的端口，工具会显示该端口对应的常见服务（如 FTP、SSH、HTTP 等）   
> 3. 对于可能的服务，工具还会显示该服务可能存在的常见漏洞信息  
> 4. 程序采用并发的方式进行端口扫描，提高扫描效率  

## 相关数组:  
> _portServices_: 存储端口与服务的映射关系   
> _serviceVulnerabilities_: 存储每个服务的常见漏洞信息。  

## 界面:  
> 提供了三个输入框供用户输入目标主机、起始端口和结束端口    
> 用户点击“开始扫描”按钮后，工具会开始扫描并展示扫描结果   

## 依赖:  
> 使用了 Go 语言的标准库 net 和 time 来处理端口扫描   
> 使用了 fyne 库来实现简单的图形界面