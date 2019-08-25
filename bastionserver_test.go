package bastionserver

import (
	"log"
	"net/http"
	"net/url"
	"os"
	"testing"
)

func TestSetProxy(t *testing.T) {
	dummyReq, _ := http.NewRequest("", "dummy.host", http.NoBody) // localhost以外のアドレス

	t.Run("setPorxy_OK_proxy無し", func(t *testing.T) {
		// 準備
		server := New()
		ul, _ := url.Parse("http://localhost:8080")
		server.addr = ul

		// 実行
		err := server.setProxy()

		// 検証
		if err != nil {
			t.Errorf("setPorxy関数の検証に失敗しました。 err: %s", err.Error())
		}

		tp := server.transport.(*http.Transport)
		proxy, _ := tp.Proxy(dummyReq)
		if got := proxy; got != nil {
			t.Errorf("setProxy関数の検証に失敗しました: got %s, want is nil", got)
		}
	})

	t.Run("setPorxy_OK_proxy有り", func(t *testing.T) {
		// 準備
		server := New()
		server.l = log.New(os.Stderr, "", log.LstdFlags)
		ul, _ := url.Parse("http://localhost:8080")
		server.addr = ul
		proxyURL, _ := url.Parse("http://proxy:8080")
		server.WithProxy(proxyURL)

		// 実行
		err := server.setProxy()

		// 検証
		if err != nil {
			t.Errorf("setPorxy関数の検証に失敗しました。 err: %s", err.Error())
		}

		tp := server.transport.(*http.Transport)
		proxy, _ := tp.Proxy(dummyReq)
		if got, want := proxy.String(), "http://proxy:8080"; got != want {
			t.Errorf("setProxy関数の検証に失敗しました: got %s, want %s", got, want)
		}
	})

	t.Run("setPorxy_NG_proxyとaddrが同じ", func(t *testing.T) {
		// 準備
		server := New()
		server.l = log.New(os.Stderr, "", log.LstdFlags)
		ul, _ := url.Parse("http://localhost:8080")
		server.addr = ul
		proxyURL, _ := url.Parse("http://localhost:8080")
		server.WithProxy(proxyURL)

		// 実行
		err := server.setProxy()

		// 検証
		if got, want := err.Error(), "bastion address unexpected same proxy addr"; got != want {
			t.Errorf("setProxy関数の検証に失敗しました: got %s, want %s", got, want)
		}
	})
}
