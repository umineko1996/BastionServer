package bastionserver

import (
	"io"
	"net/http"
)

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
	bs.l.Printf("resp: %s\n", resp.Status)
	for key := range resp.Header {
		v := resp.Header.Get(key)
		w.Header().Set(key, v)
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		bs.l.Println(err)
	}
}
