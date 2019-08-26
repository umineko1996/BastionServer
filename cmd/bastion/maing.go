package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/umineko1996/bastionserver"
)

const (
	success = iota
	failed
)

const (
	defaultAddr  = "localhost:6060" // default webserver address
	defaultProxy = ""
)

func main() {
	os.Exit(Run())
}

func Run() int {
	var pErr error
	defer func() {
		if pErr != nil {
			fmt.Println(pErr)
		}
	}()

	addr, proxy, tls := getArgs()

	server := bastionserver.New()

	if proxy != "" {
		if !strings.HasPrefix(proxy, "http") {
			proxy = "http://" + proxy
		}
		pu, err := url.Parse(proxy)
		if err != nil {
			pErr = err
			return failed
		}
		server = server.WithProxy(pu)
	}
	if tls.decrypt {
		server = server.WithTLS(tls.certFile, tls.keyFile)
	}

	switch {
	case tls.https:
		if pErr = server.ListenTLS(addr, tls.certFile, tls.keyFile); pErr != nil {
			return failed
		}
	default:
		if pErr = server.Listen(addr); pErr != nil {
			return failed
		}
	}

	return success
}

type tlsConfig struct {
	certFile string
	keyFile  string
	decrypt  bool
	https    bool
}

func getArgs() (addr, proxy string, tls *tlsConfig) {
	httpAddr := flag.String("http", defaultAddr, "bastion service address")
	proxyAddr := flag.String("proxy", defaultProxy, "proxy url")
	httpsAddr := flag.String("https", "", "bastion service use ssl/tls")
	certFile := flag.String("cert", "", "ssl/tls cert file")
	keyFile := flag.String("key", "", "ssl/tls key file")
	decrypt := flag.Bool("dave", false, "ssl decryption proxy")
	flag.Parse()

	switch {
	case *httpsAddr != "":
		tls = &tlsConfig{
			certFile: *certFile,
			keyFile:  *keyFile,
			https:    true,
			decrypt:  *decrypt,
		}
		return *httpsAddr, *proxyAddr, tls
	case *decrypt:
		tls = &tlsConfig{
			certFile: *certFile,
			keyFile:  *keyFile,
			decrypt:  true,
		}
		return *httpAddr, *proxyAddr, tls
	}

	return *httpAddr, *proxyAddr, nil
}
