package main

import (
	"fmt"

	"github.com/zan8in/oobadapter/pkg/oobadapter"
	"github.com/zan8in/oobadapter/pkg/retryhttp"
)

func main() {
	// TODO: implement OOB adapter
	err := retryhttp.Init(&retryhttp.Options{})
	if err != nil {
		return
	}

	oob, err := oobadapter.NewOOBAdapter("ceye", &oobadapter.ConnectorParams{
		Key:    "bba3368c28118247ddc4785630b8fca0",
		Domain: "7gn2sm.ceye.io",
	})
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	domains := oob.GetValidationDomain()

	fmt.Println("GetValidationDomain: ", domains)

	status, body := retryhttp.Get(domains.HTTP)
	fmt.Println(status, string(body))

	result := oob.ValidateResult(oobadapter.ValidateParams{
		Filter:     domains.JNDI,
		FilterType: oobadapter.OOBJNDI,
	})

	fmt.Println("GetResult: ", result)

}
