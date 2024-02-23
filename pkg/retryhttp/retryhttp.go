package retryhttp

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	randutil "github.com/zan8in/pins/rand"
	"github.com/zan8in/retryablehttp"
)

var (
	Client         *retryablehttp.Client
	ClientRedirect *retryablehttp.Client
	defaultTimeout = 30 * time.Second
	maxDefaultBody int64
)

type Options struct {
	Proxy           string
	Timeout         int
	Retries         int
	MaxRespBodySize int
}

func Init(options *Options) (err error) {
	if options == nil {
		options = &Options{}
	}
	if options.Timeout == 0 {
		options.Timeout = 30
	}
	if options.Retries == 0 {
		options.Retries = 3
	}
	if options.MaxRespBodySize == 0 {
		options.MaxRespBodySize = 10
	}
	po := &retryablehttp.DefaultPoolOptions
	po.Proxy = options.Proxy
	po.Timeout = options.Timeout
	po.Retries = options.Retries
	po.DisableRedirects = true

	retryablehttp.InitClientPool(po)
	if Client, err = retryablehttp.GetPool(po); err != nil {
		return err
	}

	po.DisableRedirects = false
	po.EnableRedirect(retryablehttp.FollowAllRedirect)
	retryablehttp.InitClientPool(po)
	if ClientRedirect, err = retryablehttp.GetPool(po); err != nil {
		return err
	}

	maxDefaultBody = int64(options.MaxRespBodySize * 1024 * 1024)

	return nil
}

func Get(target string) (int, []byte) {
	if len(target) == 0 {
		return 0, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, nil
	}

	req.Header.Add("User-Agent", randutil.RandomUA())

	resp, err := Client.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return 0, nil
	}

	reader := io.LimitReader(resp.Body, maxDefaultBody)
	respBody, err := io.ReadAll(reader)
	if err != nil {
		resp.Body.Close()
		return 0, nil
	}
	resp.Body.Close()

	return resp.StatusCode, respBody
}

func GetByCookie(target, cookie string) (int, []byte) {
	if len(target) == 0 {
		return 0, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, nil
	}

	req.Header.Add("User-Agent", randutil.RandomUA())
	req.Header.Add("Cookie", cookie)

	resp, err := Client.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return 0, nil
	}

	reader := io.LimitReader(resp.Body, maxDefaultBody)
	respBody, err := io.ReadAll(reader)
	if err != nil {
		resp.Body.Close()
		return 0, nil
	}
	resp.Body.Close()

	return resp.StatusCode, respBody
}

func GetWithCookie(target string) (int, string, []byte) {
	if len(target) == 0 {
		return 0, "", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, "", nil
	}

	req.Header.Add("User-Agent", randutil.RandomUA())

	resp, err := Client.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return 0, "", nil
	}

	reader := io.LimitReader(resp.Body, maxDefaultBody)
	respBody, err := io.ReadAll(reader)
	if err != nil {
		resp.Body.Close()
		return 0, "", nil
	}
	resp.Body.Close()

	return resp.StatusCode, resp.Header.Get("Set-Cookie"), respBody
}

func Post(target, body, contentType string) (int, []byte) {
	if len(target) == 0 {
		return 0, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		return 0, nil
	}

	req.Header.Add("User-Agent", randutil.RandomUA())

	if len(contentType) == 0 {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := Client.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return 0, nil
	}

	reader := io.LimitReader(resp.Body, maxDefaultBody)
	respBody, err := io.ReadAll(reader)
	if err != nil {
		resp.Body.Close()
		return 0, nil
	}
	resp.Body.Close()

	return resp.StatusCode, respBody
}
