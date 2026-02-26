package oobadapter

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

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

type Record struct {
	Timestamp time.Time
	Raw       string
	Snippet   string
	UniqueKey string
}

func (o *OOBAdapter) Poll(filterType string) ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	res := o.ValidateResult(ValidateParams{
		Filter:     "",
		FilterType: filterType,
	})
	if res.Body == "" {
		return nil, nil
	}
	return []byte(res.Body), nil
}

func (o *OOBAdapter) PollRecords(filterType string) ([]Record, error) {
	if o == nil {
		return nil, nil
	}
	body, err := o.Poll(filterType)
	if err != nil || len(body) == 0 {
		return nil, err
	}
	return splitRecords(body), nil
}

func (o *OOBAdapter) Match(body []byte, filterType string, filter string) bool {
	if o == nil || len(body) == 0 || filter == "" {
		return false
	}

	blob := strings.ToLower(string(body))
	switch o.DnsLogType {
	case CeyeName:
		return strings.Contains(blob, strings.ToLower(filter+"."))
	case DnslogcnName:
		return strings.Contains(blob, strings.ToLower(filter))
	case AlphalogName:
		return strings.Contains(blob, strings.ToLower(filter))
	case XrayName:
		xray := o.DnsLogModel.(*XrayConnector)
		if filterType == OOBHTTP {
			return strings.Contains(blob, strings.ToLower(getXrayHttpSuffix(xray.XrayHTTPUrl)+"/"+filter))
		}
		return strings.Contains(blob, strings.ToLower(xray.XrayDNSFilter+"."+filter))
	case RevsuitName:
		if filterType == OOBHTTP {
			return strings.Contains(blob, strings.ToLower("/log/"+filter))
		}
		return strings.Contains(blob, strings.ToLower(filter+".log"))
	default:
		return strings.Contains(blob, strings.ToLower(filter))
	}
}

func splitRecords(body []byte) []Record {
	s := strings.TrimSpace(string(body))
	if s == "" {
		return nil
	}

	now := time.Now().UTC()
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		var v any
		if err := json.Unmarshal([]byte(s), &v); err == nil {
			recs := recordsFromJSON(v, now)
			if len(recs) > 0 {
				return recs
			}
		}
	}

	lines := strings.Split(s, "\n")
	out := make([]Record, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, Record{
			Timestamp: now,
			Raw:       line,
			Snippet:   line,
		})
	}
	if len(out) > 0 {
		return out
	}
	return []Record{{
		Timestamp: now,
		Raw:       s,
		Snippet:   s,
	}}
}

func recordsFromJSON(v any, fallback time.Time) []Record {
	switch vv := v.(type) {
	case map[string]any:
		if data, ok := vv["data"]; ok {
			return recordsFromJSON(data, fallback)
		}
		raw, _ := json.Marshal(vv)
		s := strings.TrimSpace(string(raw))
		if s == "" {
			return nil
		}
		return []Record{{
			Timestamp: guessTimeFromMap(vv, fallback),
			Raw:       s,
			Snippet:   guessSnippetFromMap(vv, s),
			UniqueKey: guessUniqueFromMap(vv),
		}}
	case []any:
		out := make([]Record, 0, len(vv))
		for _, it := range vv {
			rs := recordsFromJSON(it, fallback)
			if len(rs) > 0 {
				out = append(out, rs...)
			}
		}
		return out
	case string:
		s := strings.TrimSpace(vv)
		if s == "" {
			return nil
		}
		return []Record{{
			Timestamp: fallback,
			Raw:       s,
			Snippet:   s,
		}}
	default:
		raw, _ := json.Marshal(v)
		s := strings.TrimSpace(string(raw))
		if s == "" {
			return nil
		}
		return []Record{{
			Timestamp: fallback,
			Raw:       s,
			Snippet:   s,
		}}
	}
}

func guessSnippetFromMap(m map[string]any, fallback string) string {
	candidates := []string{"name", "domain", "subdomain", "url", "request", "hostname", "host"}
	for _, k := range candidates {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok {
				s = strings.TrimSpace(s)
				if s != "" {
					return s
				}
			}
		}
	}
	return fallback
}

func guessUniqueFromMap(m map[string]any) string {
	keys := []string{"id", "ID", "uuid", "uid", "record_id", "recordId"}
	for _, k := range keys {
		v, ok := m[k]
		if !ok {
			continue
		}
		if s, ok := v.(string); ok {
			s = strings.TrimSpace(s)
			if s != "" {
				return s
			}
		}
		if f, ok := v.(float64); ok && f > 0 {
			return fmt.Sprintf("%.0f", f)
		}
	}
	return ""
}

func guessTimeFromMap(m map[string]any, fallback time.Time) time.Time {
	keys := []string{"time", "timestamp", "created_at", "createdAt"}
	for _, k := range keys {
		v, ok := m[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case string:
			s := strings.TrimSpace(t)
			if s == "" {
				continue
			}
			if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
				return ts
			}
			if ts, err := time.Parse(time.RFC3339, s); err == nil {
				return ts
			}
			if ts, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
				return ts
			}
		case float64:
			if t > 0 {
				sec := int64(t)
				if sec > 1_000_000_000_000 {
					return time.UnixMilli(sec).UTC()
				}
				return time.Unix(sec, 0).UTC()
			}
		}
	}
	return fallback
}

func NewOOBAdapter(dnslogType string, params *ConnectorParams) (*OOBAdapter, error) {
	if len(params.Domain) == 0 {
		return nil, fmt.Errorf("new OOBAdapter failed, Domain is empty")
	}
	if len(params.ApiUrl) == 0 {
		params.ApiUrl = "http://" + params.Domain
	} else {
		params.ApiUrl = strings.TrimSuffix(params.ApiUrl, "/")
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
	case RevsuitName:
		revsuit, err := NewRevsuitConnector(&ConnectorParams{
			Key:     params.Key,
			Domain:  params.Domain,
			HTTPUrl: params.HTTPUrl,
			ApiUrl:  params.ApiUrl,
		})
		if err != nil {
			return nil, err
		}
		return &OOBAdapter{
			DnsLogType:  dnslogType,
			Params:      params,
			DnsLogModel: revsuit,
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
	case RevsuitName:
		return o.DnsLogModel.(*RevsuitConnector).GetValidationDomain()
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
	case RevsuitName:
		revsuit := o.DnsLogModel.(*RevsuitConnector)
		return revsuit.ValidateResult(params)
	default:
		return Result{
			IsVaild:    false,
			DnslogType: o.DnsLogType,
			FilterType: params.FilterType,
			Body:       "unknown filter type",
		}
	}
}

func (o *OOBAdapter) IsVaild() bool {
	switch o.DnsLogType {
	case CeyeName:
		return o.DnsLogModel.(*CeyeConnector).IsVaild()
	case DnslogcnName:
		return o.DnsLogModel.(*DnslogcnConnector).IsVaild()
	case AlphalogName:
		return o.DnsLogModel.(*AlphalogConnector).IsVaild()
	case XrayName:
		return o.DnsLogModel.(*XrayConnector).IsVaild()
	case RevsuitName:
		return o.DnsLogModel.(*RevsuitConnector).IsVaild()
	default:
		return false
	}
}
