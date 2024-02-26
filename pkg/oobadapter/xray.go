package oobadapter

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zan8in/oobadapter/pkg/retryhttp"
	randutil "github.com/zan8in/pins/rand"
)

var (
	XrayName      = "xray"
	XrayDNS       = "dns"
	XrayHTTP      = "http"
	XraySubLength = 6
)

// https://docs.xray.cool/tools/xray/advanced/reverse
// http://x.x.x.x:8777/_/api/cland/generate/dns_domain
type XrayConnector struct {
	Domain        string // domain or ip
	XrayDNSFilter string // p-9a393c-iod8
	XrayHTTPUrl   string // http://x.x.x.x:8777/p/369d50/K5W0/
	XToken        string
	ApiUrl        string // http or https
	XrayHTTP      *Xray
	XrayDNS       *Xray
	IsAlive       bool
}

/*
DNS :

	{
	    "code": 0,
	    "data": {
	        "groupID": "iod8",
	        "isDomainNameServer": true,
	        "prefix": "p-9a393c-iod8",
	        "root": "dnslogxx.net",
	        "server": "x.x.x.x"
	    }
	}

HTTP :

	{
		"code": 0,
		"data": {
			"groupID": "K5W0",
			"url": "http://x.x.x.x:8777/p/369d50/K5W0/"
		}
	}
*/
type Xray struct {
	Code int      `json:"code"`
	Data XrayData `json:"data"`
}

type XrayData struct {
	GroupID            string `json:"groupID"`
	IsDomainNameServer bool   `json:"isDomainNameServer"`
	Prefix             string `json:"prefix"`
	Root               string `json:"root"`
	Server             string `json:"server"`
	Url                string `json:"url"`
}

func NewXrayConnector(params *ConnectorParams) (*XrayConnector, error) {
	// fmt.Println(fmt.Sprintf("%s/_/api/cland/generate/dns_domain", params.ApiUrl))
	status, body := retryhttp.GetWithHeader(fmt.Sprintf("%s/_/api/cland/generate/dns_domain", params.ApiUrl), map[string]string{
		"X-Token": params.Key,
	})
	if status == 0 {
		return nil, fmt.Errorf("get xray failed")
	}

	xrayDns := &Xray{}
	if err := json.Unmarshal(body, xrayDns); err != nil {
		return nil, err
	}

	// fmt.Println(fmt.Sprintf("%s/_/api/cland/generate/http_url", params.ApiUrl))
	status2, body2 := retryhttp.GetWithHeader(fmt.Sprintf("%s/_/api/cland/generate/http_url", params.ApiUrl), map[string]string{
		"X-Token": params.Key,
	})
	if status2 == 0 {
		return nil, fmt.Errorf("get xray failed")
	}

	xrayHttp := &Xray{}
	if err := json.Unmarshal(body2, xrayHttp); err != nil {
		return nil, err
	}

	if status != 0 {
		return &XrayConnector{
			Domain:        params.Domain,
			XrayDNSFilter: xrayDns.Data.Prefix,
			XrayHTTPUrl:   xrayHttp.Data.Url,
			XToken:        params.Key,
			XrayHTTP:      xrayHttp,
			XrayDNS:       xrayDns,
			ApiUrl:        params.ApiUrl,
			IsAlive:       true,
		}, nil
	}
	return nil, fmt.Errorf("new XrayConnector failed")
}

func (c *XrayConnector) GetValidationDomain() ValidationDomains {
	randstr := randutil.Randcase(XraySubLength)
	validationDomain := ValidationDomains{
		HTTP:   fmt.Sprintf("%s/%s", strings.TrimSuffix(c.XrayHTTPUrl, "/"), randstr), // http://x.x.x.x:8777/p/369d50/K5W0/randstr
		DNS:    fmt.Sprintf("%s.%s.%s", c.XrayDNSFilter, randstr, c.Domain),           // p-9a393c-iod8-randstr.dnslogxx.net
		Filter: randstr,
	}
	return validationDomain
}

func (c *XrayConnector) ValidateResult(params ValidateParams) Result {
	switch c.GetFilterType(params.FilterType) {
	case XrayDNS:
		return c.validate(params)
	case XrayHTTP:
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

func (c *XrayConnector) validate(params ValidateParams) Result {
	url := ""
	if params.FilterType == OOBHTTP {
		url = fmt.Sprintf("%s/_/api/cland/event/list?lastID=&count=10&eventType=http&action=Next", c.ApiUrl)
	}
	if params.FilterType == OOBDNS {
		url = fmt.Sprintf("%s/_/api/cland/event/list?lastID=&count=10&eventType=dns&action=Next", c.ApiUrl)
	}
	status, body := retryhttp.GetWithHeader(url, map[string]string{
		"X-Token": c.XToken,
	})
	if status != 0 {
		if params.FilterType == OOBHTTP {
			// fmt.Println("OOBHTTP : ", getXrayHttpSuffix(c.XrayHTTPUrl)+"/"+params.Filter)
			// if strings.Contains(strings.ToLower(string(body)), strings.ToLower(getXrayHttpSuffix(c.XrayHTTPUrl)+"/"+params.Filter)) {
			if strings.Contains(strings.ToLower(string(body)), strings.ToLower("/"+params.Filter)) {
				return Result{
					IsVaild:    true,
					DnslogType: AlphalogName,
					FilterType: params.FilterType,
					Body:       string(body),
				}
			}
		}
		if params.FilterType == OOBDNS {
			// fmt.Println("OOBDNS : ", c.XrayDNSFilter+"."+params.Filter)
			// if strings.Contains(strings.ToLower(string(body)), strings.ToLower(c.XrayDNSFilter+"."+params.Filter)) {
			if strings.Contains(strings.ToLower(string(body)), strings.ToLower(c.XrayDNSFilter+".")) {
				return Result{
					IsVaild:    true,
					DnslogType: AlphalogName,
					FilterType: params.FilterType,
					Body:       string(body),
				}
			}
		}
	}
	return Result{
		IsVaild:    false,
		DnslogType: AlphalogName,
		FilterType: params.FilterType,
		Body:       string(body),
	}
}

func (c *XrayConnector) GetFilterType(t string) string {
	switch t {
	case OOBHTTP:
		return XrayHTTP
	case OOBDNS:
		return XrayDNS
	default:
		return XrayDNS
	}
}

func getXrayHttpSuffix(str string) string {
	r := strings.SplitAfter(str, "/p/")
	if len(r) == 2 {
		return strings.TrimSuffix("/p/"+r[1], "/")
	}
	return ""
}

func (c *XrayConnector) IsVaild() bool {
	if c != nil {
		return c.IsAlive
	}
	return false
}
