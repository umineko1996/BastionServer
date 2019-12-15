package bastionserver

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

func (bs *BastionServer) connHTTPSTunnel(w http.ResponseWriter, r *http.Request) {
	dstAddr := r.Host
	if bs.proxy != nil {
		bs.l.Println("connection proxy")
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

	if bs.cert != nil {
		bs.l.Println("decryption proxy")
		src, dst = bs.decryptionHTTPS(src, dst, r.URL.Hostname())
	}

	go bs.duplexCommunication(src, dst)
}

func (bs *BastionServer) duplexCommunication(conn1, conn2 net.Conn) {
	defer conn1.Close()
	defer conn2.Close()
	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(conn1, conn2); err != nil {
			//bs.l.Println(err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := io.Copy(conn2, conn1); err != nil {
			//bs.l.Println(err)
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
	bs.l.Printf("connection proxy = %s\n", bs.proxy.Host)
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

func (bs *BastionServer) decryptionHTTPS(src, dst net.Conn, targetServerName string) (tlsSrc, tlsDst net.Conn) {
	// bs.tlsConfigに指定されたルート認証局情報を使用し、ターゲットドメインの証明書を作成する
	// https://golang.org/src/crypto/tls/generate_cert.go
	cert, err := bs.createCert(targetServerName)
	if err != nil {
		bs.l.Panic(err)
	}
	srcConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	tlsSrc = tls.Server(src, srcConfig)
	dstConfig := &tls.Config{
		ServerName:             targetServerName,
		SessionTicketsDisabled: true,
		// InsecureSkipVerify: true,
	}
	tlsDst = tls.Client(dst, dstConfig)

	bs.locker.Lock()
	n := bs.connN
	bs.connN++
	bs.locker.Unlock()

	return &dumpConn{base: tlsSrc, l: bs.l, number: n}, tlsDst
}

func (bs *BastionServer) createCert(host string) (*tls.Certificate, error) {
	template := x509.Certificate{
		IsCA:                  false,
		SerialNumber:          big.NewInt(23),
		Subject:               pkix.Name{},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		Issuer:                bs.cert.Leaf.Subject,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, bs.cert.Leaf, bs.cert.Leaf.PublicKey, bs.cert.PrivateKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{derBytes, bs.cert.Leaf.Raw},
		PrivateKey:  bs.cert.PrivateKey,
	}

	return cert, nil
}

type dumpConn struct {
	base   net.Conn
	l      *log.Logger
	number int
}

func (dc *dumpConn) Close() error {
	return dc.base.Close()
}
func (dc *dumpConn) LocalAddr() net.Addr {
	return dc.base.LocalAddr()
}
func (dc *dumpConn) RemoteAddr() net.Addr {
	return dc.base.RemoteAddr()
}
func (dc *dumpConn) SetDeadline(t time.Time) error {
	return dc.base.SetDeadline(t)
}
func (dc *dumpConn) SetReadDeadline(t time.Time) error {
	return dc.base.SetReadDeadline(t)
}
func (dc *dumpConn) SetWriteDeadline(t time.Time) error {
	return dc.base.SetWriteDeadline(t)
}

func (dc *dumpConn) Read(b []byte) (n int, err error) {
	n, err = dc.base.Read(b)
	if err != nil {
		return n, err
	}
	dc.dumpRequest(b)

	return n, err
}
func (dc *dumpConn) Write(b []byte) (n int, err error) {
	dc.dumpResponse(b)
	return dc.base.Write(b)
}

func (dc *dumpConn) dumpRequest(b []byte) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b)))
	if err != nil {
		//dc.l.Printf("read request failed: %s\n", err)
		return
	}
	dump, err := httputil.DumpRequest(req, false)
	if err != nil {
		//dc.l.Printf("dump request failed: %s\n", err)
		return
	}
	dc.l.Printf("REQUEST DUMP N=%d\n", dc.number)
	dc.l.Writer().Write(dump)
}

func (dc *dumpConn) dumpResponse(b []byte) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(b)), nil)
	if err != nil {
		//dc.l.Printf("read resuponse failed: %s\n", err)
		return
	}
	dump, err := httputil.DumpResponse(resp, false)
	if err != nil {
		//dc.l.Printf("dump resuponse failed: %s\n", err)
		return
	}
	dc.l.Printf("RESPONSE DUMP N=%d\n", dc.number)
	dc.l.Writer().Write(dump)
}
