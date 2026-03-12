package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/zan8in/oobadapter/pkg/oobadapter"
	"github.com/zan8in/oobadapter/pkg/retryhttp"
)

func main() {
	oob, err := oobadapter.NewOOBAdapter("revsuit", &oobadapter.ConnectorParams{
		Key:     "xxx",
		Domain:  "log.xxx.top",
		HTTPUrl: "http://xxx.com/log",
		ApiUrl:  "http://xxx.com/xx-ls",
	})
	if err != nil {
		fmt.Printf("[init] err=%v\n", err)
		return
	}

	fmt.Printf("[init] adapter=revsuit alive=%v\n", oob.IsVaild())
	if !oob.IsVaild() {
		return
	}

	httpOK, httpBody := runHTTPCheck(oob)
	dnsOK, dnsBody := runDNSCheck(oob)

	fmt.Println("------------------------------------------------------------")
	fmt.Printf("[summary] http=%v dns=%v\n", httpOK, dnsOK)
	if !httpOK {
		fmt.Printf("[summary] http_last_body=%s\n", trimBody(httpBody, 300))
	}
	if !dnsOK {
		fmt.Printf("[summary] dns_last_body=%s\n", trimBody(dnsBody, 300))
	}
	if httpOK && dnsOK {
		fmt.Println("[summary] PASS")
	} else {
		fmt.Println("[summary] FAIL")
	}
}

func runHTTPCheck(oob *oobadapter.OOBAdapter) (bool, string) {
	d := oob.GetValidationDomain()
	fmt.Println("------------------------------------------------------------")
	fmt.Printf("[http] filter=%s url=%s\n", d.Filter, d.HTTP)

	status, body := retryhttp.Get(d.HTTP)
	fmt.Printf("[http] trigger_status=%d\n", status)

	ok, lastBody := pollValidate(oob, oobadapter.OOBHTTP, d.Filter, 10*time.Second, 1*time.Second)
	fmt.Printf("[http] ok=%v\n", ok)
	if !ok && lastBody == "" {
		lastBody = string(body)
	}
	return ok, lastBody
}

func runDNSCheck(oob *oobadapter.OOBAdapter) (bool, string) {
	d := oob.GetValidationDomain()
	// d.Filter = "jpfne" + d.Filter
	// d.DNS = "jpfne" + d.DNS
	fmt.Println("------------------------------------------------------------")
	fmt.Printf("[dns] filter=%s domain=%s\n", d.Filter, d.DNS)

	cmd := exec.Command("ping", "-c", "1", d.DNS)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[dns] trigger_err=%v\n", err)
	}
	if len(out) > 0 {
		fmt.Printf("[dns] trigger_out=%s\n", trimBody(string(out), 300))
	}

	ok, lastBody := pollValidate(oob, oobadapter.OOBDNS, d.Filter, 15*time.Second, 1*time.Second)
	fmt.Printf("[dns] ok=%v\n", ok)
	return ok, lastBody
}

func pollValidate(oob *oobadapter.OOBAdapter, filterType, filter string, maxWait, interval time.Duration) (bool, string) {
	deadline := time.Now().Add(maxWait)
	lastBody := ""
	for attempt := 1; ; attempt++ {
		res := oob.ValidateResult(oobadapter.ValidateParams{
			Filter:     filter,
			FilterType: filterType,
		})
		lastBody = res.Body
		if res.IsVaild {
			return true, lastBody
		}
		if time.Now().After(deadline) {
			return false, lastBody
		}
		time.Sleep(interval)
	}
}

func trimBody(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
