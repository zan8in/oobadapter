package oobadapter

import (
	"fmt"

	"github.com/zan8in/oobadapter/pkg/retryhttp"
)

func init() {
	if err := retryhttp.Init(&retryhttp.Options{}); err != nil {
		fmt.Println("retryhttp init error: ", err)
	}
}

var (
	OOBHTTP = "http"
	OOBDNS  = "dns"
	OOBJNDI = "jndi"
)

type OOBAdapter struct {
	DnsLogType  string
	Params      *ConnectorParams
	DnsLogModel interface{}
}

func NewOOBAdapter(dnslogType string, params *ConnectorParams) *OOBAdapter {
	return &OOBAdapter{
		DnsLogType: dnslogType,
		Params:     params,
	}
}

func (o *OOBAdapter) GetValidationDomain() ValidationDomains {
	switch o.DnsLogType {
	case CeyeName:
		ceye := NewCeyeConnector(&ConnectorParams{
			Key:    o.Params.Key,
			Domain: o.Params.Domain,
		})
		o.DnsLogModel = ceye
		return ceye.GetValidationDomain()
	default:
		return ValidationDomains{}
	}
}

func (o *OOBAdapter) ValidateResult(params ValidateParams) bool {
	switch o.DnsLogType {
	case CeyeName:
		ceye := o.DnsLogModel.(*CeyeConnector)
		return ceye.ValidateResult(ValidateParams{
			Filter:     ceye.Filter,
			FilterType: ceye.FilterType(params.FilterType),
		})
	default:
		return false
	}
}
