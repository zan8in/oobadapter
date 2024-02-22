package oobadapter

import (
	"bytes"
	"fmt"
	"time"

	"github.com/zan8in/oobadapter/pkg/retryhttp"
	randutil "github.com/zan8in/pins/rand"
)

var (
	DnslogcnSubLength = 10
)

// http://dnslog.cn/getdomain.php?t=0.12843715100488828
// http://dnslog.cn/getrecords.php?t=0.12843715100488828
type DnslogcnConnector struct {
	Token  string // your ceye api token.
	Domain string // your ceye identifier.
	Filter string // match url name rule, the filter max length is 20.
}

func NewDnslogcnConnector(params *ConnectorParams) *DnslogcnConnector {
	status, body := retryhttp.Get(fmt.Sprintf("http://dnslog.cn/getdomain.php?t=0.%d", time.Now().UnixNano()))
	if status != 0 && bytes.Contains(body, []byte(params.Domain)) {
		return &DnslogcnConnector{
			Domain: params.Domain,
			Filter: string(body),
		}
	}
	return &DnslogcnConnector{
		Token:  params.Key,
		Domain: params.Domain,
	}
}

func (c *DnslogcnConnector) GetValidationDomain() ValidationDomains {
	filter := randutil.Randcase(DnslogcnSubLength)
	validationDomain := ValidationDomains{
		HTTP: fmt.Sprintf("http://%s.%s", filter, c.Domain),
		DNS:  fmt.Sprintf("%s.%s", filter, c.Domain),
		JNDI: fmt.Sprintf("%s.%s", filter, c.Domain),
	}
	return validationDomain
}
