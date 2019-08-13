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
	transport http.RoundTripper
	addr      *url.URL
	proxy     *url.URL
	l         *log.Logger
}

func New() *BastionServer {
	return &BastionServer{
		transport: http.DefaultTransport,
	}
}
func (bs *BastionServer) WithTransport(transport http.RoundTripper) *BastionServer {
	bs.transport = transport
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
	if bs.proxy != nil {
		http.DefaultTransport.(*http.Transport).Proxy = http.ProxyURL(bs.proxy)
	}
	dummyReq, err := http.NewRequest("", "dummy.host", http.NoBody) // localhost以外のアドレス
	if err != nil {
		log.Panic(err)
	}
	transport, ok := bs.transport.(*http.Transport)
	if !ok {
		bs.l.Println("proxy used, RoundTripper type must be Transport")
		return nil
	}
	proxyURL, err := transport.Proxy(dummyReq)
	if err != nil {
		return err
	} else if proxyURL == nil {
		return nil
	}
	bs.l.Printf("use proxy = %s\n", proxyURL)
	if proxyURL.Host == bastionURL.Host {
		return errors.New("bastion address unexpected same proxy addr")
	}
	// MEMO 基本はローカルホスト指定のはずだが、IP指定とホスト名指定で一致しないかもしれないので一応チェック
	if (proxyURL.Hostname() == "localhost" || proxyURL.Hostname() == "127.0.0.1") && proxyURL.Port() == bastionURL.Port() {
		return errors.New("bastion address unexpected same proxy addr")
	}
	bs.proxy = proxyURL
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
	if bastionURL.Hostname() == "" {
		bastionURL.Host = "localhost:" + bastionURL.Port()
	}
	bs.addr = bastionURL
	if err := bs.setProxy(bastionURL); err != nil {
		return err
	}
	bs.l.Printf("bastion server listen = %s\n", bs.addr.Host)
	return http.ListenAndServe(bastionURL.Host, bs)
}
func (bs *BastionServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	bs.l.Printf("req: %#v", r)
	if r.Method == http.MethodConnect {
		bs.connHTTPSTunnel(w, r)
	} else {
		bs.sendHTTPRequest(w, r)
	}
}

func (bs *BastionServer) connHTTPSTunnel(w http.ResponseWriter, r *http.Request) {
}

func (bs *BastionServer) sendHTTPRequest(w http.ResponseWriter, r *http.Request) {
	transport := bs.transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	r.RequestURI = ""
	r.Header.Del("Accept-Encoding")
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Connection")
	resp, err := transport.RoundTrip(r)
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
	for key, _ := range resp.Header {
		v := resp.Header.Get(key)
		w.Header().Set(key, v)
	}
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
