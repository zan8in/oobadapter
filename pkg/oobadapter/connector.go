package oobadapter

type ValidationDomains struct {
	// DnsLogType string // dnslog 类型，比如：ceye
	Filter string // 过滤规则，一般是随机字符串，比如：filterxxx
	HTTP   string // http 格式，比如：http://filterxxx.yyy.ceye.io
	DNS    string // dnslog 格式，比如：filterxxx.yyy.ceye.io
	JNDI   string // j3ndi 格式，比如：filterxxx.yyy.ceye.io
}

type ValidateParams struct {
	Filter     string // 用于验证的过滤规则
	FilterType string // filter 类型，比如：http, dns, jndi
}

type Result struct {
	IsVaild    bool
	DnslogType string
	FilterType string
	Body       string
}

type Connector interface {
	GetValidationDomain() ValidationDomains
	ValidateResult(params ValidateParams) Result
	GetFilterType(t string) string
}

type ConnectorParams struct {
	Key    string // 密钥
	Domain string // 子域名
}