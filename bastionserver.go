package bastionserver

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

type BastionServer struct {
	transport http.RoundTripper
	addr      *url.URL
	proxy     *url.URL
	l         *log.Logger
	tlsConfig *tls.Config
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

func (bs *BastionServer) WithTLS(certFile, keyFile string) *BastionServer {
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
		bs.l.Println("key file no such specified")
		return bs
	}

	config := &tls.Config{}
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0] = certificate
	bs.tlsConfig = config
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
	bs.l.Printf("req: %s", r.URL)
	if r.Method == http.MethodConnect {
		bs.l.Printf("request is CONNECT method")
		bs.connHTTPSTunnel(w, r)
	} else {
		bs.sendHTTPRequest(w, r)
	}
}

func (bs *BastionServer) connHTTPSTunnel(w http.ResponseWriter, r *http.Request) {
	dstAddr := r.Host
	if bs.proxy != nil {
		bs.l.Printf("connection proxy")
		dstAddr = bs.proxy.Host
	}

	dst, err := net.Dial("tcp", dstAddr)
	if err != nil {
		bs.l.Println(err)
		http.Error(w, "bastion server error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if bs.proxy != nil {
		if err := bs.sendConnectMethodRequest(dst, r.Host); err != nil {
			bs.l.Println(err)
			http.Error(w, "bastion server error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	hij, ok := w.(http.Hijacker)
	if !ok {
		dst.Close()
		bs.l.Panic("httpserver does not support hijacking")
	}
	src, _, err := hij.Hijack()
	if err != nil {
		dst.Close()
		bs.l.Panic("Cannot hijack connection " + err.Error())
	}
	src.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))

	if bs.tlsConfig != nil {
		bs.l.Println("decryption proxy")
		src, dst = bs.decryptionHTTPS(src, dst, r.URL.Hostname())
	}

	go bs.duplexCommunication(src, dst)
}

func (bs *BastionServer) decryptionHTTPS(src, dst net.Conn, targetServerName string) (tlsSrc, tlsDst net.Conn) {
	// TODO bs.tlsConfigに指定されたルート認証局情報を使用し、ターゲットドメインの証明書を作成する必要がある
	srcConfig := cloneTLSConfig(bs.tlsConfig)
	tlsSrc = tls.Server(src, srcConfig)
	dstConfig := &tls.Config{
		ServerName:             targetServerName,
		SessionTicketsDisabled: true,
	}
	tlsDst = tls.Client(dst, dstConfig)
	return tlsSrc, tlsDst
}

func cloneTLSConfig(config *tls.Config) *tls.Config {
	newConfig := new(tls.Config)
	newConfig.Certificates = make([]tls.Certificate, 1)
	newConfig.Certificates[0] = config.Certificates[0]

	return newConfig
}

func (bs *BastionServer) duplexCommunication(conn1, conn2 net.Conn) {
	defer conn1.Close()
	defer conn2.Close()
	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(conn1, conn2); err != nil {
			bs.l.Println(err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := io.Copy(conn2, conn1); err != nil {
			bs.l.Println(err)
		}
	}()
	wg.Wait()
}

func (bs *BastionServer) sendConnectMethodRequest(proxy net.Conn, targetAddr string) error {
	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: targetAddr},
		Host:   targetAddr,
		Header: make(http.Header),
	}
	if pa := bs.proxyAuth(); pa != "" {
		connectReq.Header.Set("Proxy-Authorization", pa)
	}
	connectReq.Write(proxy)
	br := bufio.NewReader(proxy)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		f := strings.SplitN(resp.Status, " ", 2)
		if len(f) < 2 {
			return errors.New("unknown status code")
		}
		return errors.New(f[1])
	}
	bs.l.Printf("connection proxy = %s", bs.proxy.Host)
	return nil
}

func (bs *BastionServer) proxyAuth() string {
	if bs.proxy == nil {
		return ""
	}
	if u := bs.proxy.User; u != nil {
		username := u.Username()
		password, _ := u.Password()
		return "Basic " + basicAuth(username, password)
	}
	return ""
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
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
		http.Error(w, "bastion server error: "+err.Error(), http.StatusInternalServerError)
	}
	bs.l.Printf("resp: %s", resp.Status)
	for key := range resp.Header {
		v := resp.Header.Get(key)
		w.Header().Set(key, v)
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		bs.l.Println(err)
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
