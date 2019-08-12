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

const defaultAddr = "localhost:6060" // default webserver address

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

	addr, proxy := getArgs()

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

	if pErr = server.Listen(addr); pErr != nil {
		return failed
	}

	return success
}

func getArgs() (addr, proxy string) {
	httpAddr := flag.String("http", defaultAddr, "bastion service address")
	proxyAddr := flag.String("proxy", "", "proxy url")
	flag.Parse()

	return *httpAddr, *proxyAddr
}
