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

func NewOOBAdapter(dnslogType string, params *ConnectorParams) (*OOBAdapter, error) {
	switch dnslogType {
	case CeyeName:
		ceye := NewCeyeConnector(&ConnectorParams{
			Key:    params.Key,
			Domain: params.Domain,
		})
		return &OOBAdapter{
			DnsLogType:  dnslogType,
			Params:      params,
			DnsLogModel: ceye,
		}, nil
	default:
		return nil, fmt.Errorf("new oobadapter failed")
	}
}

func (o *OOBAdapter) GetValidationDomain() ValidationDomains {
	switch o.DnsLogType {
	case CeyeName:
		return o.DnsLogModel.(*CeyeConnector).GetValidationDomain()
	default:
		return ValidationDomains{}
	}
}

func (o *OOBAdapter) ValidateResult(params ValidateParams) Result {
	switch o.DnsLogType {
	case CeyeName:
		ceye := o.DnsLogModel.(*CeyeConnector)
		return ceye.ValidateResult(params)
	default:
		return Result{
			IsVaild:    false,
			DnslogType: o.DnsLogType,
			FilterType: params.FilterType,
			Body:       "unknown filter type",
		}
	}
}
