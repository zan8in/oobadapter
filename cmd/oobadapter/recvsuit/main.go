package main

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/zan8in/oobadapter/pkg/oobadapter"
	"github.com/zan8in/oobadapter/pkg/retryhttp"
)

func main() {
	// 初始化 OOB 对象，设置 dnslog 配置
	oob, err := oobadapter.NewOOBAdapter("revsuit", &oobadapter.ConnectorParams{
		Key:     "helploghelplog",
		Domain:  "log.bastatic.com",
		HTTPUrl: "http://141.98.212.54/log",
		ApiUrl:  "http://141.98.212.54/helplog",
	})
	if err != nil {
		fmt.Println("err:", err.Error())
		return
	}

	b := oob.IsVaild()
	if b {
		fmt.Println("Xray IsVaild: ", b)
	} else {
		fmt.Println("Xray IsVaild: ", b)
		return
	}

	// 获取验证域名
	domains := oob.GetValidationDomain()

	fmt.Println("GetValidationDomain: ", domains)

	// 模拟 dnslog 请求（正式环境无需请求）
	fmt.Println(domains.HTTP)
	retryhttp.Get(domains.HTTP)
	// fmt.Println(status, string(body))

	time.Sleep(time.Second * 3)
	// 获取验证结果
	result := oob.ValidateResult(oobadapter.ValidateParams{
		Filter:     domains.Filter,
		FilterType: oobadapter.OOBHTTP,
	})

	fmt.Println("GetResult: ", result.IsVaild, result.FilterType, result.Body)

	//----------------------------------------

	// 获取验证域名
	domains = oob.GetValidationDomain()

	fmt.Println("GetValidationDomain: ", domains)

	// 模拟 dnslog 请求（正式环境无需请求）
	command := "ping" // Windows系统的查看目录命令
	args := []string{"-n", "1", domains.DNS}
	cmd := exec.Command(command, args...)
	if err := cmd.Start(); err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(time.Second * 3)

	// 获取验证结果
	result = oob.ValidateResult(oobadapter.ValidateParams{
		Filter:     domains.Filter,
		FilterType: oobadapter.OOBDNS,
	})

	fmt.Println("GetResult: ", result.IsVaild, result.FilterType, result.Body)
}
