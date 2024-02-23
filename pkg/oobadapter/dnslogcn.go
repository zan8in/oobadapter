package oobadapter

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/zan8in/oobadapter/pkg/retryhttp"
	randutil "github.com/zan8in/pins/rand"
)

var (
	DnslogcnName      = "dnslogcn"
	DnslogcnDNS       = "dns"
	DnslogcnHTTP      = "http"
	DnslogcnSubLength = 6
)

// http://dnslog.cn/getdomain.php?t=0.12843715100488828
// http://dnslog.cn/getrecords.php?t=0.12843715100488828
type DnslogcnConnector struct {
	Domain         string // your dnslog identifier.
	DnslogcnFilter string // match url name rule, the filter max length is 20.
	Cookie         string
}

func NewDnslogcnConnector(params *ConnectorParams) (*DnslogcnConnector, error) {
	status, cookie, body := retryhttp.GetWithCookie(fmt.Sprintf("http://dnslog.cn/getdomain.php?t=0.%d", time.Now().UnixNano()))

	if status != 0 && bytes.Contains(body, []byte("."+params.Domain)) {
		return &DnslogcnConnector{
			Domain:         params.Domain,
			DnslogcnFilter: string(bytes.TrimSpace(body)),
			Cookie:         cookie,
		}, nil
	}
	return nil, fmt.Errorf("new dnslogcnconnector failed")
}

func (c *DnslogcnConnector) GetValidationDomain() ValidationDomains {
	filter := fmt.Sprintf("%s.%s", randutil.Randcase(DnslogcnSubLength), c.DnslogcnFilter)
	validationDomain := ValidationDomains{
		HTTP:   fmt.Sprintf("http://%s", filter),
		DNS:    filter,
		JNDI:   filter,
		Filter: filter,
	}
	return validationDomain
}

func (c *DnslogcnConnector) ValidateResult(params ValidateParams) Result {
	switch c.GetFilterType(params.FilterType) {
	case DnslogcnDNS:
		return c.validate(params)
	case DnslogcnHTTP:
		return c.validate(params)
	default:
		return Result{
			IsVaild:    false,
			DnslogType: DnslogcnName,
			FilterType: params.FilterType,
			Body:       "unknown filter type",
		}
	}
}

func (c *DnslogcnConnector) validate(params ValidateParams) Result {
	url := fmt.Sprintf("http://dnslog.cn/getrecords.php?t=0.%d", time.Now().UnixNano())
	status, body := retryhttp.GetByCookie(url, c.Cookie)
	fmt.Println("=======", params.Filter)
	if status != 0 {
		if strings.Contains(strings.ToLower(string(body)), strings.ToLower(params.Filter)) {
			return Result{
				IsVaild:    true,
				DnslogType: DnslogcnName,
				FilterType: params.FilterType,
				Body:       string(body),
			}
		}
	}
	return Result{
		IsVaild:    false,
		DnslogType: DnslogcnName,
		FilterType: params.FilterType,
		Body:       string(body),
	}
}

func (c *DnslogcnConnector) GetFilterType(t string) string {
	switch t {
	case OOBHTTP:
		return DnslogcnDNS
	case OOBDNS:
		return DnslogcnDNS
	default:
		return DnslogcnDNS
	}
}
