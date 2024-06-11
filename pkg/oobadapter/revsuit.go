package oobadapter

import (
	"fmt"
	"strings"

	"github.com/zan8in/oobadapter/pkg/retryhttp"
	randutil "github.com/zan8in/pins/rand"
)

var (
	RevsuitName      = "revsuit"
	RevsuitDNS       = "dns"
	RevsuitHTTP      = "http"
	RevsuitSubLength = 8
)

type RevsuitConnector struct {
	Token     string // your Revsuit api token.
	HTTPUrl   string // your Revsuit httplog url.
	DnsDomain string // your Revsuit dnslog domain.
	Filter    string // match url name rule, the filter max length is 20.
	ApiUrl    string
	IsAlive   bool
}

func NewRevsuitConnector(params *ConnectorParams) (*RevsuitConnector, error) {
	url := fmt.Sprintf("%s/api/record/dns?page=1&pageSize=1&order=desc", params.ApiUrl)
	cookie := fmt.Sprintf("token=%s", params.Key)
	if status, _ := retryhttp.GetByCookie(url, cookie); status != 0 {
		return &RevsuitConnector{
			Token:     params.Key,
			DnsDomain: params.Domain,
			HTTPUrl:   params.HTTPUrl,
			Filter:    randutil.Randcase(RevsuitSubLength),
			ApiUrl:    params.ApiUrl,
			IsAlive:   true,
		}, nil
	} else {
		return nil, fmt.Errorf("new RevsuitConnector failed")
	}
}

func (c *RevsuitConnector) GetValidationDomain() ValidationDomains {
	randomFilter := randutil.Randcase(RevsuitSubLength)
	validationDomain := ValidationDomains{
		HTTP:   fmt.Sprintf("%s/%s", strings.TrimSuffix(c.HTTPUrl, "/"), randomFilter), // http://x.x.x.x:8777/log/randstr
		DNS:    fmt.Sprintf("%s.%s", randomFilter, c.DnsDomain),                        // xxx.log.xxx.net
		Filter: randomFilter,
	}
	return validationDomain
}

func (c *RevsuitConnector) ValidateResult(params ValidateParams) Result {
	switch c.GetFilterType(params.FilterType) {
	case RevsuitDNS:
		return c.validate(params)
	case RevsuitHTTP:
		return c.validate(params)
	default:
		return Result{
			IsVaild:    false,
			DnslogType: RevsuitName,
			FilterType: params.FilterType,
			Body:       "unknown filter type",
		}
	}
}

func (c *RevsuitConnector) GetFilterType(t string) string {
	switch t {
	case OOBHTTP:
		return RevsuitHTTP
	case OOBDNS:
		return RevsuitDNS
	default:
		return RevsuitDNS
	}
}

func (c *RevsuitConnector) validate(params ValidateParams) Result {
	url := ""
	cookie := fmt.Sprintf("token=%s", c.Token)
	if params.FilterType == OOBHTTP {
		url = fmt.Sprintf("%s/api/record/http?page=1&pageSize=100&order=desc", c.ApiUrl)
	}
	if params.FilterType == OOBDNS {
		url = fmt.Sprintf("%s/api/record/dns?page=1&pageSize=100&order=desc", c.ApiUrl)
	}
	status, body := retryhttp.GetByCookie(url, cookie)
	if status != 0 {
		if params.FilterType == OOBHTTP {
			if strings.Contains(strings.ToLower(string(body)), strings.ToLower("/log/"+params.Filter)) {
				return Result{
					IsVaild:    true,
					DnslogType: RevsuitName,
					FilterType: params.FilterType,
					Body:       string(body),
				}
			}
		}
		if params.FilterType == OOBDNS {
			if strings.Contains(strings.ToLower(string(body)), strings.ToLower(params.Filter+".log")) {
				return Result{
					IsVaild:    true,
					DnslogType: RevsuitName,
					FilterType: params.FilterType,
					Body:       string(body),
				}
			}
		}
	}
	return Result{
		IsVaild:    false,
		DnslogType: RevsuitName,
		FilterType: params.FilterType,
		Body:       string(body),
	}
}

func (c *RevsuitConnector) IsVaild() bool {
	if c != nil {
		return c.IsAlive
	}
	return false
}
