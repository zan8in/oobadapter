package oobadapter

import (
	"fmt"
	"strings"

	"github.com/zan8in/oobadapter/pkg/retryhttp"
	randutil "github.com/zan8in/pins/rand"
)

var (
	CeyeName      = "ceye"
	CeyeDNS       = "dns"
	CeyeHTTP      = "http"
	CeyeSubLength = 10
)

// http://api.ceye.io/v1/records?token={token}&type={dns|http}&filter={filter}
type CeyeConnector struct {
	Token  string // your ceye api token.
	Domain string // your ceye identifier.
	// Type   string // type of query, 'dns' or 'request'.
	Filter string // match url name rule, the filter max length is 20.
}

func (c *CeyeConnector) GetValidationDomain() ValidationDomains {
	filter := randutil.Randcase(CeyeSubLength)
	validationDomain := ValidationDomains{
		HTTP:       fmt.Sprintf("http://%s.%s", filter, c.Domain),
		DNS:        fmt.Sprintf("%s.%s", filter, c.Domain),
		JNDI:       fmt.Sprintf("%s.%s", filter, c.Domain),
		DnsLogType: CeyeName,
		Filter:     filter,
	}
	return validationDomain
}

func (c *CeyeConnector) ValidateResult(params ValidateParams) bool {
	switch params.FilterType {
	case CeyeDNS:
		return c.validate(params)
	case CeyeHTTP:
		return c.validate(params)
	default:
		return false
	}
}

func (c *CeyeConnector) validate(params ValidateParams) bool {
	url := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=%s&filter=%s", c.Token, params.FilterType, params.Filter)
	status, body := retryhttp.Get(url)
	fmt.Println(string(body))
	if status != 0 {
		if strings.Contains(strings.ToLower(string(body)), strings.ToLower(params.Filter+".")) {
			return true
		}
	}
	return false
}

func NewCeyeConnector(params *ConnectorParams) *CeyeConnector {
	return &CeyeConnector{
		Token:  params.Key,
		Domain: params.Domain,
		// Type:   CeyeDNS,
	}
}

func (c *CeyeConnector) FilterType(t string) string {
	switch t {
	case OOBHTTP:
		return CeyeHTTP
	case OOBDNS:
		return CeyeDNS
	default:
		return CeyeDNS
	}
}
