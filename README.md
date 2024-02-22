# oobadapter
OOBAdapter is a framework that consolidates diverse Out-of-Band (OOB) tools into a unified interface.

"Out of Band" (OOB) refers to a situation where information is transmitted outside the data channel. In the realm of security, OOB is typically used to describe a communication method employed by attackers to bypass defensive measures. OOB communication involves attackers transmitting information or executing operations through an indirect method, circumventing primary communication channels. This technique is often utilized to evade network security devices, firewalls, or other monitoring and blocking measures.

# Example
### ceye demo

[ceye.io](http://ceye.io/)

```go
package main

import (
	"fmt"

	"github.com/zan8in/oobadapter/pkg/oobadapter"
	"github.com/zan8in/oobadapter/pkg/retryhttp"
)

func main() {

	// 初始化 OOB 对象，设置 ceye 配置
	oob, err := oobadapter.NewOOBAdapter("ceye", &oobadapter.ConnectorParams{
		Key:    "bba33xxxb8fca0",
		Domain: "7gxxm.ceye.io",
	})
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// 获取验证域名
	domains := oob.GetValidationDomain()

	fmt.Println("GetValidationDomain: ", domains)

	// 模拟 dnslog 请求（正式环境无需请求）
	retryhttp.Get(domains.HTTP)
	// fmt.Println(status, string(body))

	// 获取验证结果
	result := oob.ValidateResult(oobadapter.ValidateParams{
		Filter:     domains.Filter,
		FilterType: oobadapter.OOBDNS,
	})

	fmt.Println("GetResult: ", result.IsVaild, result.FilterType, result.Body)

}

```

### Dnslog.cn Demo

[dnslog.cn](http://dnslog.cn/)

```golang
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
	
}
```

### Alphalog Demo

[Alphalog](https://github.com/AlphabugX/Alphalog)

```go
package main

import (
	"fmt"
	"strings"

	"github.com/zan8in/oobadapter/pkg/oobadapter"
	"github.com/zan8in/oobadapter/pkg/retryhttp"
)

func main() {

	// 初始化 OOB 对象，设置 dnslog 配置
	oob, err := oobadapter.NewOOBAdapter("alphalog", &oobadapter.ConnectorParams{
		Domain: "yourdomain.top",
		ApiUrl: "http://yourdomain.top/",
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

	retryhttp.Get(strings.ReplaceAll(domains.LDAP, "ldap://jndi.", "http://"))
	// fmt.Println(status, string(body))

	// 获取验证结果
	result = oob.ValidateResult(oobadapter.ValidateParams{
		Filter:     domains.Filter,
		FilterType: oobadapter.OOBLDAP,
	})

	fmt.Println("GetResult: ", result.IsVaild, result.FilterType, result.Body)

}
```