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
	Scheme   string // http or https
	Alphalog Alphalog
}

type Alphalog struct {
	Key       string
	Subdomain string
	Rmi       string
	Ldap      string
}

func NewAlphalogConnector(params *ConnectorParams) (*AlphalogConnector, error) {
	status, body := retryhttp.Get(fmt.Sprintf("%s://%s/get", params.Scheme, params.Domain))
	fmt.Println(fmt.Sprintf("%s://%s/get", params.Scheme, params.Domain))
	fmt.Println(status, string(body))
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
			Scheme:   params.Scheme,
			Token:    alog.Key,
			Alphalog: alog,
		}, nil
	}

	return nil, fmt.Errorf("new AlphalogConnector failed")
}

func (c *AlphalogConnector) GetValidationDomain() ValidationDomains {
	filter := fmt.Sprintf("%s.%s", randutil.Randcase(AlphalogSubLength), c.Alphalog.Subdomain)
	validationDomain := ValidationDomains{
		HTTP: fmt.Sprintf("http://%s", filter),
		DNS:  filter,
		JNDI: fmt.Sprintf("%s/%s", c.Alphalog.Ldap, randutil.Randcase(AlphalogSubLength)),
		RMI:  fmt.Sprintf("%s/%s", c.Alphalog.Rmi, randutil.Randcase(AlphalogSubLength)),
		LDAP: fmt.Sprintf("%s/%s", c.Alphalog.Ldap, randutil.Randcase(AlphalogSubLength)),
	}
	return validationDomain
}

func (c *AlphalogConnector) ValidateResult(params ValidateParams) Result {
	// switch c.GetFilterType(params.FilterType) {
	// case DnslogcnDNS:
	// 	return c.validate(params)
	// case DnslogcnHTTP:
	// 	return c.validate(params)
	// default:
	// 	return Result{
	// 		IsVaild:    false,
	// 		DnslogType: AlphalogName,
	// 		FilterType: params.FilterType,
	// 		Body:       "unknown filter type",
	// 	}
	// }
	return c.validate(params)
}

func (c *AlphalogConnector) validate(params ValidateParams) Result {
	url := fmt.Sprintf("%s://%s", c.Scheme, c.Domain)
	status, body := retryhttp.Post(url, "key="+c.Token, "")
	if status != 0 {
		if strings.Contains(strings.ToLower(string(body)), strings.ToLower(params.Filter+".")) {
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
