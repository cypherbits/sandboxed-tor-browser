package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"git.schwanenlied.me/yawning/hpkp.git"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: hpkp-headers <url>")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	h := hpkp.ParseHeader(resp)
	j, _ := json.Marshal(h)
	fmt.Println(string(j))

	h = hpkp.ParseReportOnlyHeader(resp)
	j, _ = json.Marshal(h)
	fmt.Println(string(j))
}
