package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/RuneStone0/vdp-hunter/go/internal/dnsq"
)

func main() {
	c := dnsq.New([]string{"1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53"}, 2*time.Second)
	for _, n := range os.Args[1:] {
		t := time.Now()
		ip, ok, err := c.Resolve(n)
		_, sysErr := net.LookupHost(n)
		fmt.Printf("%-28s dnsq=%v ip=%-15s err=%v sys=%v %s\n", n, ok, ip, err, sysErr == nil, time.Since(t).Round(time.Millisecond))
	}
}
