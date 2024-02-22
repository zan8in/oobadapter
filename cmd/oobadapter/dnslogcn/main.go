package main

import (
	"fmt"

	"github.com/zan8in/oobadapter/pkg/oobadapter"
	"github.com/zan8in/oobadapter/pkg/retryhttp"
)

func main() {

	// 初始化 OOB 对象，设置 dnslog 配置
	oob, err := oobadapter.NewOOBAdapter("dnslogcn", &oobadapter.ConnectorParams{
		Domain: "dnslog.cn",
	})
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// 获取验证域名
	domains := oob.GetValidationDomain()

	fmt.Println("GetValidationDomain: ", domains)

	// 模拟 dnslog 请求（正式环境无需请求）
	fmt.Println(domains.HTTP)
	status, body := retryhttp.Get(domains.HTTP)
	fmt.Println(status, string(body))

	// 获取验证结果
	result := oob.ValidateResult(oobadapter.ValidateParams{
		Filter:     domains.Filter,
		FilterType: oobadapter.OOBDNS,
	})

	fmt.Println("GetResult: ", result.IsVaild, result.FilterType, result.Body)

	//----------------------------------------

	// 获取验证域名
	domains = oob.GetValidationDomain()

	fmt.Println("GetValidationDomain: ", domains)

	// 模拟 dnslog 请求（正式环境无需请求）
	retryhttp.Get(domains.HTTP)
	// fmt.Println(status, string(body))

	// 获取验证结果
	result = oob.ValidateResult(oobadapter.ValidateParams{
		Filter:     domains.Filter,
		FilterType: oobadapter.OOBHTTP,
	})

	fmt.Println("GetResult: ", result.IsVaild, result.FilterType, result.Body)

	//----------------------------------------

	// 获取验证域名
	domains2 := oob.GetValidationDomain()

	fmt.Println("GetValidationDomain: ", domains2)

	// 模拟 dnslog 请求（正式环境无需请求）
	retryhttp.Get(domains2.HTTP)
	// fmt.Println(status, string(body))

	// 获取验证结果
	result = oob.ValidateResult(oobadapter.ValidateParams{
		Filter:     domains2.Filter,
		FilterType: oobadapter.OOBJNDI,
	})

	fmt.Println("GetResult: ", result.IsVaild, result.FilterType, result.Body)

}
