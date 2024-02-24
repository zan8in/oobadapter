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
	OOBRMI  = "rmi"
	OOBLDAP = "ldap"
)

type OOBAdapter struct {
	DnsLogType  string
	Params      *ConnectorParams
	DnsLogModel interface{}
}

func NewOOBAdapter(dnslogType string, params *ConnectorParams) (*OOBAdapter, error) {
	if len(params.Domain) == 0 {
		return nil, fmt.Errorf("new OOBAdapter failed, Domain is empty")
	}
	if len(params.ApiUrl) == 0 {
		params.ApiUrl = "http://" + params.Domain
	}
	switch dnslogType {
	case CeyeName:
		ceye := NewCeyeConnector(&ConnectorParams{
			Key:    params.Key,
			Domain: params.Domain,
			ApiUrl: params.ApiUrl,
		})
		return &OOBAdapter{
			DnsLogType:  dnslogType,
			Params:      params,
			DnsLogModel: ceye,
		}, nil
	case DnslogcnName:
		dnslogcn, err := NewDnslogcnConnector(&ConnectorParams{
			Domain: params.Domain,
			ApiUrl: params.ApiUrl,
		})
		if err != nil {
			return nil, err
		}
		return &OOBAdapter{
			DnsLogType:  dnslogType,
			Params:      params,
			DnsLogModel: dnslogcn,
		}, nil
	case AlphalogName:
		alphalog, err := NewAlphalogConnector(&ConnectorParams{
			Key:    params.Key,
			Domain: params.Domain,
			ApiUrl: params.ApiUrl,
		})
		if err != nil {
			return nil, err
		}
		return &OOBAdapter{
			DnsLogType:  dnslogType,
			Params:      params,
			DnsLogModel: alphalog,
		}, nil
	case XrayName:
		xray, err := NewXrayConnector(&ConnectorParams{
			Key:    params.Key,
			Domain: params.Domain,
			ApiUrl: params.ApiUrl,
		})
		if err != nil {
			return nil, err
		}
		return &OOBAdapter{
			DnsLogType:  dnslogType,
			Params:      params,
			DnsLogModel: xray,
		}, nil
	default:
		return nil, fmt.Errorf("new oobadapter failed")
	}
}

func (o *OOBAdapter) GetValidationDomain() ValidationDomains {
	switch o.DnsLogType {
	case CeyeName:
		return o.DnsLogModel.(*CeyeConnector).GetValidationDomain()
	case DnslogcnName:
		return o.DnsLogModel.(*DnslogcnConnector).GetValidationDomain()
	case AlphalogName:
		return o.DnsLogModel.(*AlphalogConnector).GetValidationDomain()
	case XrayName:
		return o.DnsLogModel.(*XrayConnector).GetValidationDomain()
	default:
		return ValidationDomains{}
	}
}

func (o *OOBAdapter) ValidateResult(params ValidateParams) Result {
	switch o.DnsLogType {
	case CeyeName:
		ceye := o.DnsLogModel.(*CeyeConnector)
		return ceye.ValidateResult(params)
	case DnslogcnName:
		dnslogcn := o.DnsLogModel.(*DnslogcnConnector)
		return dnslogcn.ValidateResult(params)
	case AlphalogName:
		alphalog := o.DnsLogModel.(*AlphalogConnector)
		return alphalog.ValidateResult(params)
	case XrayName:
		xray := o.DnsLogModel.(*XrayConnector)
		return xray.ValidateResult(params)
	default:
		return Result{
			IsVaild:    false,
			DnslogType: o.DnsLogType,
			FilterType: params.FilterType,
			Body:       "unknown filter type",
		}
	}
}
