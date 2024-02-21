package main

import (
	"fmt"

	"github.com/zan8in/oobadapter/pkg/oobadapter"
	"github.com/zan8in/oobadapter/pkg/retryhttp"
)

func main() {

	// 初始化 OOB 对象，设置 ceye 配置
	oob := oobadapter.NewOOBAdapter("ceye", &oobadapter.ConnectorParams{
		Key:    "bba3368c28118247ddc4785630b8fca0",
		Domain: "7gn2sm.ceye.io",
	})

	// 获取验证域名
	domains := oob.GetValidationDomain()

	fmt.Println("GetValidationDomain: ", domains)

	// 模拟 dnslog 请求（正式环境无需请求）
	status, body := retryhttp.Get(domains.HTTP)
	fmt.Println(status, string(body))

	// 获取验证结果
	result := oob.ValidateResult(oobadapter.ValidateParams{
		Filter:     domains.Filter,
		FilterType: oobadapter.OOBJNDI,
	})

	fmt.Println("GetResult: ", result)

}
