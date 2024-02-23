package oobadapter

import (
	"fmt"
	"strings"

	"github.com/zan8in/oobadapter/pkg/retryhttp"
	randutil "github.com/zan8in/pins/rand"
)

var (
	CeyeName      = "ceyeio"
	CeyeDNS       = "dns"
	CeyeHTTP      = "http"
	CeyeSubLength = 8
)

// http://api.ceye.io/v1/records?token={token}&type={dns|http}&filter={filter}
type CeyeConnector struct {
	Token      string // your ceye api token.
	Domain     string // your ceye identifier.
	CeyeFilter string // match url name rule, the filter max length is 20.
}

func (c *CeyeConnector) GetValidationDomain() ValidationDomains {
	filter := fmt.Sprintf("%s.%s", randutil.Randcase(CeyeSubLength), c.CeyeFilter)
	validationDomain := ValidationDomains{
		HTTP:   fmt.Sprintf("http://%s.%s", filter, c.Domain),
		DNS:    fmt.Sprintf("%s.%s", filter, c.Domain),
		JNDI:   fmt.Sprintf("%s.%s", filter, c.Domain),
		Filter: filter,
	}
	return validationDomain
}

func (c *CeyeConnector) ValidateResult(params ValidateParams) Result {
	switch c.GetFilterType(params.FilterType) {
	case CeyeDNS:
		return c.validate(params)
	case CeyeHTTP:
		return c.validate(params)
	default:
		return Result{
			IsVaild:    false,
			DnslogType: CeyeName,
			FilterType: params.FilterType,
			Body:       "unknown filter type",
		}
	}
}

func (c *CeyeConnector) validate(params ValidateParams) Result {
	url := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=%s&filter=%s", c.Token, c.GetFilterType(params.FilterType), params.Filter)
	status, body := retryhttp.Get(url)
	if status != 0 {
		if strings.Contains(strings.ToLower(string(body)), strings.ToLower(params.Filter)) {
			return Result{
				IsVaild:    true,
				DnslogType: CeyeName,
				FilterType: params.FilterType,
				Body:       string(body),
			}
		}
	}
	return Result{
		IsVaild:    false,
		DnslogType: CeyeName,
		FilterType: params.FilterType,
		Body:       string(body),
	}
}

func NewCeyeConnector(params *ConnectorParams) *CeyeConnector {
	return &CeyeConnector{
		Token:      params.Key,
		Domain:     params.Domain,
		CeyeFilter: randutil.Randcase(CeyeSubLength),
	}
}

func (c *CeyeConnector) GetFilterType(t string) string {
	switch t {
	case OOBHTTP:
		return CeyeHTTP
	case OOBDNS:
		return CeyeDNS
	default:
		return CeyeDNS
	}
}
