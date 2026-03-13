package oobadapter

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
)

var (
	InteractshName = "interactsh"
)

type InteractshConnector struct {
	c       *client.Client
	mu      sync.Mutex
	records []server.Interaction
	isAlive bool
}

func NewInteractshConnector(params *ConnectorParams) (*InteractshConnector, error) {
	opts := *client.DefaultOptions

	if s := strings.TrimSpace(params.Domain); s != "" {
		opts.ServerURL = s
	}
	if t := strings.TrimSpace(params.Key); t != "" {
		opts.Token = t
	}

	cli, err := client.New(&opts)
	if err != nil {
		return nil, err
	}
	ic := &InteractshConnector{
		c:       cli,
		records: make([]server.Interaction, 0, 64),
		isAlive: true,
	}

	_ = cli.StartPolling(2*time.Second, func(interaction *server.Interaction) {
		if interaction == nil {
			return
		}
		ic.mu.Lock()
		ic.records = append(ic.records, *interaction)
		if len(ic.records) > 500 {
			ic.records = ic.records[len(ic.records)-500:]
		}
		ic.mu.Unlock()
	})

	return ic, nil
}

func (c *InteractshConnector) GetValidationDomain() ValidationDomains {
	if c == nil || c.c == nil {
		return ValidationDomains{}
	}
	u := strings.TrimSpace(c.c.URL())
	if u == "" {
		return ValidationDomains{}
	}
	httpURL := u
	if !strings.Contains(httpURL, "://") {
		httpURL = "https://" + httpURL
	}
	pu, err := url.Parse(httpURL)
	host := ""
	if err == nil {
		host = strings.TrimSpace(pu.Hostname())
	}
	if host == "" {
		host = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(httpURL, "https://"), "http://"))
		host = strings.TrimSpace(strings.Split(host, "/")[0])
		host = strings.TrimSpace(strings.Split(host, ":")[0])
	}
	filter := host
	if parts := strings.Split(host, "."); len(parts) > 0 && strings.TrimSpace(parts[0]) != "" {
		filter = strings.TrimSpace(parts[0])
	}

	return ValidationDomains{
		HTTP:   httpURL,
		DNS:    host,
		Filter: filter,
	}
}

func (c *InteractshConnector) ValidateResult(params ValidateParams) Result {
	if c == nil {
		return Result{IsVaild: false, DnslogType: InteractshName, FilterType: params.FilterType}
	}
	filterType := strings.ToLower(strings.TrimSpace(params.FilterType))
	filter := strings.ToLower(strings.TrimSpace(params.Filter))

	c.mu.Lock()
	all := append([]server.Interaction(nil), c.records...)
	c.mu.Unlock()

	out := make([]server.Interaction, 0, len(all))
	matched := false
	for _, it := range all {
		protoLower := strings.ToLower(strings.TrimSpace(it.Protocol))
		if filterType != "" && protoLower != "" && protoLower != filterType {
			if !(filterType == OOBHTTP && (protoLower == "https" || protoLower == "http")) {
				continue
			}
		}
		if filter == "" {
			out = append(out, it)
			continue
		}
		if strings.Contains(strings.ToLower(it.FullId), filter) || strings.Contains(strings.ToLower(it.UniqueID), filter) {
			matched = true
			out = append(out, it)
		}
	}

	bodyBytes, _ := json.Marshal(map[string]any{
		"data": out,
	})
	body := string(bodyBytes)
	if filter == "" {
		return Result{IsVaild: len(out) > 0, DnslogType: InteractshName, FilterType: params.FilterType, Body: body}
	}
	return Result{IsVaild: matched, DnslogType: InteractshName, FilterType: params.FilterType, Body: body}
}

func (c *InteractshConnector) IsVaild() bool {
	if c == nil {
		return false
	}
	return c.isAlive && c.c != nil
}

func (c *InteractshConnector) GetFilterType(t string) string {
	switch t {
	case OOBHTTP:
		return OOBHTTP
	case OOBDNS:
		return OOBDNS
	default:
		return OOBDNS
	}
}

func (c *InteractshConnector) String() string {
	if c == nil || c.c == nil {
		return "interactsh<nil>"
	}
	return fmt.Sprintf("interactsh<%s>", c.c.URL())
}
