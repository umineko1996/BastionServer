package bastionserver

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
)

type BastionServer struct {
	transport http.RoundTripper
	addr      *url.URL
	proxy     *url.URL
	l         *log.Logger
	cert      *tls.Certificate
	connN     int
	locker    sync.Mutex
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

func (bs *BastionServer) WithNonProxy() *BastionServer {
	os.Setenv("https_proxy", "")
	os.Setenv("http_proxy", "")
	os.Setenv("HTTPS_PROXY", "")
	os.Setenv("http_proxy", "")
	bs.proxy = nil
	return bs
}

func (bs *BastionServer) WithLogger(logger *log.Logger) *BastionServer {
	bs.l = logger
	return bs
}

func (bs *BastionServer) WithTLSDecryption(certFile, keyFile string) *BastionServer {
	if bs.l == nil {
		bs.l = log.New(os.Stderr, "", log.LstdFlags)
	}
	if certFile == "" {
		bs.l.Println("cert file no such specified")
		return bs
	}
	if keyFile == "" {
		bs.l.Println("key file no such specified")
		return bs
	}

	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		bs.l.Println(err)
		return bs
	}

	certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		bs.l.Println(err)
		return bs
	}
	bs.cert = &certificate

	return bs
}

func (bs *BastionServer) init(addr string) error {
	if bs.l == nil {
		bs.l = log.New(os.Stderr, "", log.LstdFlags)
	}
	bastionURL, err := url.Parse(addr)
	if err != nil {
		return err
	}
	if bastionURL.Hostname() == "" {
		bastionURL.Host = "localhost:" + bastionURL.Port()
	}
	bs.addr = bastionURL
	if err := bs.setProxy(); err != nil {
		return err
	}
	bs.l.Printf("bastion server listen = %s\n", bs.addr.Host)
	return nil
}

func (bs *BastionServer) setProxy() error {
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
		bs.l.Println("not use proxy")
		return nil
	}
	bs.l.Printf("use proxy = %s\n", proxyURL)
	if proxyURL.Host == bs.addr.Host {
		return errors.New("bastion address unexpected same proxy addr")
	}
	// MEMO 基本はローカルホスト指定のはずだが、IP指定とホスト名指定で一致しないかもしれないので一応チェック
	if (proxyURL.Hostname() == "localhost" || proxyURL.Hostname() == "127.0.0.1") && proxyURL.Port() == bs.addr.Port() {
		return errors.New("bastion address unexpected same proxy addr")
	}
	bs.proxy = proxyURL
	return nil
}

func (bs *BastionServer) Listen(addr string) error {
	if err := bs.init("http://" + addr); err != nil {
		return err
	}
	return http.ListenAndServe(bs.addr.Host, bs)
}

func (bs *BastionServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	bs.l.Printf("req: %s\n", r.URL)
	if r.Method == http.MethodConnect {
		bs.l.Println("request is CONNECT method")
		bs.connHTTPSTunnel(w, r)
	} else {
		bs.sendHTTPRequest(w, r)
	}
}

func (bs *BastionServer) ListenTLS(addr, certFile, keyFile string) error {
	bs.l.Println("bastion server listen ssl/tls (https)")
	if certFile == "" {
		return errors.New("cert file no such specified")
	}
	if keyFile == "" {
		return errors.New("key file no such specified")
	}
	if err := bs.init("https://" + addr); err != nil {
		return err
	}

	return http.ListenAndServeTLS(bs.addr.Host, certFile, keyFile, bs)
}

// Listen はデフォルト設定のbastionserverを起動します
// デフォルト起動のポートは:8080です
// 細かな設定をしたい場合はNew関数でbastionserverを作成してListenメソッドを実行してください
func Listen() error {
	return http.ListenAndServe(":8080", new(BastionServer))
}
