package oobadapter

import (
	"encoding/json"
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
		if matched, filteredBody := filterRevsuitBody(params.FilterType, c.DnsDomain, params.Filter, body); matched {
			return Result{
				IsVaild:    true,
				DnslogType: RevsuitName,
				FilterType: params.FilterType,
				Body:       filteredBody,
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

type revsuitAPIResponse struct {
	Error  any `json:"error"`
	Result struct {
		Count int              `json:"count"`
		Data  []map[string]any `json:"data"`
	} `json:"result"`
	Status string `json:"status"`
}

func filterRevsuitBody(filterType, dnsDomain, filter string, body []byte) (bool, string) {
	filterLower := strings.ToLower(strings.TrimSpace(filter))
	if filterLower == "" || len(body) == 0 {
		return false, string(body)
	}

	resp := revsuitAPIResponse{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return filterRevsuitBodyFallback(filterType, dnsDomain, filterLower, body)
	}

	domainLower := strings.ToLower(strings.TrimSpace(dnsDomain))
	matched := false
	out := make([]map[string]any, 0, len(resp.Result.Data))
	for _, it := range resp.Result.Data {
		if it == nil {
			continue
		}
		if matchRevsuitRecord(filterType, domainLower, filterLower, it) {
			matched = true
			out = append(out, it)
		}
	}
	if !matched {
		return false, string(body)
	}

	resp.Result.Data = out
	resp.Result.Count = len(out)
	b, err := json.Marshal(resp)
	if err != nil {
		return true, string(body)
	}
	return true, string(b)
}

func filterRevsuitBodyFallback(filterType, dnsDomainLower, filterLower string, body []byte) (bool, string) {
	bodyLower := strings.ToLower(string(body))
	switch filterType {
	case OOBHTTP:
		if strings.Contains(bodyLower, "/log/"+filterLower) {
			return true, string(body)
		}
	case OOBDNS:
		domainLower := strings.ToLower(strings.TrimSpace(dnsDomainLower))
		if strings.Contains(bodyLower, `"`+"flag"+`":"`+filterLower+`"`) ||
			(domainLower != "" && strings.Contains(bodyLower, filterLower+"."+domainLower)) ||
			strings.Contains(bodyLower, filterLower+".") {
			return true, string(body)
		}
	}
	return false, string(body)
}

func matchRevsuitRecord(filterType, dnsDomainLower, filterLower string, it map[string]any) bool {
	switch filterType {
	case OOBHTTP:
		uri := strings.ToLower(strings.TrimSpace(stringAny(it["uri"])))
		flag := strings.ToLower(strings.TrimSpace(stringAny(it["flag"])))
		token := "/log/" + filterLower
		return strings.Contains(uri, token) || strings.Contains(flag, token)
	case OOBDNS:
		domain := strings.ToLower(strings.TrimSpace(stringAny(it["domain"])))
		flag := strings.ToLower(strings.TrimSpace(stringAny(it["flag"])))
		if dnsDomainLower != "" && domain != "" && !strings.HasSuffix(domain, dnsDomainLower) {
			return false
		}
		if hasTokenSegment(flag, filterLower) {
			return true
		}
		return hasTokenSegment(domain, filterLower)
	default:
		return false
	}
}

func stringAny(v any) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(v)
	}
}

func hasTokenSegment(s, token string) bool {
	if s == "" || token == "" {
		return false
	}
	parts := strings.Split(s, ".")
	for _, p := range parts {
		if p == token {
			return true
		}
	}
	return strings.HasPrefix(s, token+".") || strings.Contains(s, "."+token+".")
}

func (c *RevsuitConnector) IsVaild() bool {
	if c != nil {
		return c.IsAlive
	}
	return false
}
