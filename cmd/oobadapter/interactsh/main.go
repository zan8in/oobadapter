package main

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/zan8in/oobadapter/pkg/oobadapter"
	"github.com/zan8in/oobadapter/pkg/retryhttp"
)

func main() {
	oob, err := oobadapter.NewOOBAdapter("interactsh", &oobadapter.ConnectorParams{
		Domain: "oast.pro",
	})
	if err != nil {
		fmt.Printf("[init] err=%v\n", err)
		return
	}
	fmt.Printf("[init] adapter=interactsh alive=%v\n", oob.IsVaild())
	if !oob.IsVaild() {
		return
	}

	d := oob.GetValidationDomain()
	fmt.Printf("[payload] filter=%s http=%s dns=%s\n", d.Filter, d.HTTP, d.DNS)

	status, _ := retryhttp.Get(d.HTTP)
	fmt.Printf("[http] trigger_status=%d\n", status)

	_ = exec.Command("ping", "-c", "1", d.DNS).Run()
	fmt.Printf("[dns] triggered\n")

	time.Sleep(5 * time.Second)

	httpRes := oob.ValidateResult(oobadapter.ValidateParams{
		Filter:     d.Filter,
		FilterType: oobadapter.OOBHTTP,
	})
	fmt.Printf("[http] ok=%v\n", httpRes.IsVaild)

	dnsRes := oob.ValidateResult(oobadapter.ValidateParams{
		Filter:     d.Filter,
		FilterType: oobadapter.OOBDNS,
	})
	fmt.Printf("[dns] ok=%v\n", dnsRes.IsVaild)
}
