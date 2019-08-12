package bastionserver

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
)

type BastionServer struct {
	client *http.Client
	addr   *url.URL
	proxy  *url.URL
	l      *log.Logger
}

func New() *BastionServer {
	return &BastionServer{
		client: http.DefaultClient,
	}
}

func (bs *BastionServer) WithClient(client *http.Client) *BastionServer {
	bs.client = client
	return bs
}

func (bs *BastionServer) WithProxy(proxyURL *url.URL) *BastionServer {
	bs.proxy = proxyURL
	return bs
}

func (bs *BastionServer) WithLogger(logger *log.Logger) *BastionServer {
	bs.l = logger
	return bs
}

func (bs *BastionServer) setProxy(bastionURL *url.URL) error {
	if bs.proxy == nil {
		return nil
	}

	http.DefaultTransport.(*http.Transport).Proxy = http.ProxyURL(bs.proxy)

	dummyReq, err := http.NewRequest("", "dummy.host", http.NoBody) // localhost以外のアドレス
	if err != nil {
		log.Panic(err)
	}

	if bs.client.Transport == nil {
		bs.client.Transport = http.DefaultTransport
	}
	proxyURL, err := bs.client.Transport.(*http.Transport).Proxy(dummyReq)
	if err != nil {
		return err
	} else if proxyURL == nil {
		return nil
	}

	if proxyURL.Host == bastionURL.Host {
		bs.l.Printf("proxy: %s, bastion: %s\n", proxyURL.Host, bastionURL.Host)
		return errors.New("bastion address unexpected same proxy addr")
	}
	// MEMO 基本はローカルホスト指定のはずだが、IP指定とホスト名指定で一致しないかもしれないので一応チェック
	if (proxyURL.Hostname() == "localhost" || proxyURL.Hostname() == "127.0.0.1") && proxyURL.Port() == bastionURL.Port() {
		return errors.New("bastion address unexpected same proxy addr")
	}

	return nil
}

func (bs *BastionServer) Listen(addr string) error {
	if bs.l == nil {
		bs.l = log.New(os.Stderr, "", log.Ldate)
	}

	bastionURL, err := url.Parse("http://" + addr)
	if err != nil {
		return err
	}
	bs.addr = bastionURL

	if err := bs.setProxy(bastionURL); err != nil {
		return err
	}

	bs.l.Printf("bastion=%s, proxy=%s\n", bs.addr, bs.proxy)
	return http.ListenAndServe(bastionURL.Host, bs)
}

func (bs *BastionServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	client := bs.client
	if client == nil {
		client = http.DefaultClient
	}

	bs.l.Printf("req: %s", r.URL.RequestURI())

	resp, err := client.Do(r)
	if err != nil {
		bs.l.Println(err)

		code := http.StatusInternalServerError
		buf := bytes.NewBufferString("bastion server error: " + err.Error())
		resp = &http.Response{
			Status:     http.StatusText(code),
			StatusCode: code,
			Body:       ioutil.NopCloser(buf),
		}
	}
	bs.l.Printf("resp: %s", resp.Status)

	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		bs.l.Println(err)
	}
}

// Listen はデフォルト設定のbastionserverを起動します
// デフォルト起動のポートは:8080です
// 細かな設定をしたい場合はNew関数でbastionserverを作成してListenメソッドを実行してください
func Listen() error {
	return http.ListenAndServe(":8080", new(BastionServer))
}
