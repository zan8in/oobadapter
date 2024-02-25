package oobadapter

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zan8in/oobadapter/pkg/retryhttp"
	randutil "github.com/zan8in/pins/rand"
)

var (
	AlphalogName      = "alphalog"
	AlphalogDNS       = "dns"
	AlphalogHTTP      = "http"
	AlphalogJNDI      = "jndi"
	AlphalogRMI       = "rmi"
	AlphalogLDAP      = "ldap"
	AlphalogSubLength = 8
)

// http://api.Alphalog.io/v1/records?token={token}&type={dns|http}&filter={filter}
type AlphalogConnector struct {
	Token    string // your Alphalog api token.
	Domain   string // your Alphalog identifier.
	ApiUrl   string // http or https
	Alphalog Alphalog
	IsAlive  bool
}

type Alphalog struct {
	Key       string
	Subdomain string
	Rmi       string
	Ldap      string
}

func NewAlphalogConnector(params *ConnectorParams) (*AlphalogConnector, error) {
	apiurl := strings.TrimRight(params.ApiUrl, "/")
	status, body := retryhttp.Get(fmt.Sprintf("%s/get", apiurl))
	if status == 0 {
		return nil, fmt.Errorf("new AlphalogConnector failed")
	}

	alog := Alphalog{}
	if err := json.Unmarshal(body, &alog); err != nil {
		return nil, err
	}

	if len(alog.Key) > 0 && len(alog.Subdomain) > 0 {
		return &AlphalogConnector{
			Domain:   params.Domain,
			ApiUrl:   apiurl,
			Token:    alog.Key,
			Alphalog: alog,
			IsAlive:  true,
		}, nil
	}

	return nil, fmt.Errorf("new AlphalogConnector failed")
}

func (c *AlphalogConnector) GetValidationDomain() ValidationDomains {
	filter := fmt.Sprintf("%s.%s", randutil.Randcase(AlphalogSubLength), c.Alphalog.Subdomain)
	validationDomain := ValidationDomains{
		HTTP:   fmt.Sprintf("http://%s", filter),
		DNS:    filter,
		JNDI:   fmt.Sprintf("%s/%s", c.Alphalog.Ldap, randutil.Randcase(AlphalogSubLength)),
		RMI:    fmt.Sprintf("%s/%s", c.Alphalog.Rmi, randutil.Randcase(AlphalogSubLength)),
		LDAP:   fmt.Sprintf("%s/%s", c.Alphalog.Ldap, randutil.Randcase(AlphalogSubLength)),
		Filter: filter,
	}
	return validationDomain
}

func (c *AlphalogConnector) ValidateResult(params ValidateParams) Result {
	return c.validate(params)
}

func (c *AlphalogConnector) validate(params ValidateParams) Result {
	status, body := retryhttp.Post(c.ApiUrl, "key="+c.Token, "")
	if status != 0 {
		if strings.Contains(strings.ToLower(string(body)), strings.ToLower(params.Filter)) {
			return Result{
				IsVaild:    true,
				DnslogType: AlphalogName,
				FilterType: params.FilterType,
				Body:       string(body),
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

func (c *AlphalogConnector) GetFilterType(t string) string {
	switch t {
	case OOBHTTP:
		return AlphalogHTTP
	case OOBDNS:
		return AlphalogDNS
	case OOBJNDI:
		return AlphalogJNDI
	case OOBRMI:
		return AlphalogRMI
	case OOBLDAP:
		return AlphalogLDAP
	default:
		return AlphalogDNS
	}
}
func (c *AlphalogConnector) IsVaild() bool {
	if c != nil {
		return c.IsAlive
	}
	return false
}
