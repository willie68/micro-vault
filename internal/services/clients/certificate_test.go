package clients

import (
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"
)

func TestMergeDNSSingles(t *testing.T) {
	ast := assert.New(t)

	crt := make(map[string]any)
	crt["dns"] = "willie.host"
	dnss, err := mergeDNSs(crt, nil)
	ast.Nil(err)
	ast.Equal(1, len(dnss))
	ast.True(slices.Contains(dnss, "willie.host"))

	dnss, err = mergeDNSs(nil, []string{"local.host", "remote.host"})
	ast.Nil(err)
	ast.Equal(2, len(dnss))
	ast.True(slices.Contains(dnss, "remote.host"))
	ast.True(slices.Contains(dnss, "local.host"))
}

func TestMergeDNSSimple(t *testing.T) {
	ast := assert.New(t)

	crt := make(map[string]any)
	crt["dns"] = "willie.host"
	dnss, err := mergeDNSs(crt, []string{"local.host", "remote.host"})
	ast.Nil(err)
	ast.Equal(3, len(dnss))
	ast.True(slices.Contains(dnss, "willie.host"))
	ast.True(slices.Contains(dnss, "remote.host"))
	ast.True(slices.Contains(dnss, "local.host"))
}

func TestMergeDNSDoublets(t *testing.T) {
	ast := assert.New(t)

	crt := make(map[string]any)
	crt["dns"] = "willie.host"
	dnss, err := mergeDNSs(crt, []string{"willie.host", "local.host", "remote.host"})
	ast.Nil(err)
	ast.Equal(3, len(dnss))
	ast.True(slices.Contains(dnss, "willie.host"))
	ast.True(slices.Contains(dnss, "remote.host"))
	ast.True(slices.Contains(dnss, "local.host"))
}

func TestMergeDNSList(t *testing.T) {
	ast := assert.New(t)

	crt := make(map[string]any)
	crt["dns"] = []string{"willie.host"}
	dnss, err := mergeDNSs(crt, []string{"local.host", "remote.host"})
	ast.Nil(err)
	ast.Equal(3, len(dnss))
	ast.True(slices.Contains(dnss, "willie.host"))
	ast.True(slices.Contains(dnss, "remote.host"))
	ast.True(slices.Contains(dnss, "local.host"))
}

func TestMergeDNSListInterface(t *testing.T) {
	ast := assert.New(t)

	crt := make(map[string]any)
	crt["dns"] = []interface{}{"willie.host"}
	dnss, err := mergeDNSs(crt, []string{"local.host", "remote.host"})
	ast.Nil(err)
	ast.Equal(3, len(dnss))
	ast.True(slices.Contains(dnss, "willie.host"))
	ast.True(slices.Contains(dnss, "remote.host"))
	ast.True(slices.Contains(dnss, "local.host"))
}

func TestMergeIPSingles(t *testing.T) {
	ast := assert.New(t)

	ip := net.ParseIP("192.168.178.10")
	crt := make(map[string]any)
	crt["ip"] = ip.String()
	ips, err := mergeIPs(crt, nil)
	ast.Nil(err)
	ast.Equal(1, len(ips))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), ip.String())
	}))

	ips, err = mergeIPs(nil, []net.IP{net.ParseIP("127.0.0.1"), ip})
	ast.Nil(err)
	ast.Equal(2, len(ips))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), ip.String())
	}))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), "127.0.0.1")
	}))
}

func TestMergeIPSimple(t *testing.T) {
	ast := assert.New(t)

	ip := net.ParseIP("192.168.178.10")
	crt := make(map[string]any)
	crt["ip"] = ip.String()
	ips, err := mergeIPs(crt, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.178.11")})
	ast.Nil(err)
	ast.Equal(3, len(ips))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), ip.String())
	}))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), "127.0.0.1")
	}))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), "192.168.178.11")
	}))
}

func TestMergeIPDoublets(t *testing.T) {
	ast := assert.New(t)

	ip := net.ParseIP("192.168.178.10")

	crt := make(map[string]any)
	crt["ip"] = ip.String()
	ips, err := mergeIPs(crt, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.178.11"), ip})
	ast.Nil(err)
	ast.Equal(3, len(ips))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), ip.String())
	}))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), "127.0.0.1")
	}))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), "192.168.178.11")
	}))
}

func TestMergeIPList(t *testing.T) {
	ast := assert.New(t)

	ip := net.ParseIP("192.168.178.10")

	crt := make(map[string]any)
	crt["ip"] = []string{ip.String()}
	ips, err := mergeIPs(crt, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.178.11")})
	ast.Nil(err)
	ast.Equal(3, len(ips))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), ip.String())
	}))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), "127.0.0.1")
	}))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), "192.168.178.11")
	}))
}

func TestMergeIPListInterface(t *testing.T) {
	ast := assert.New(t)

	ip := net.ParseIP("192.168.178.10")

	crt := make(map[string]any)
	crt["ip"] = []interface{}{"192.168.178.11", ip}
	ips, err := mergeIPs(crt, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.178.11")})
	ast.Nil(err)
	ast.Equal(3, len(ips))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), ip.String())
	}))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), "127.0.0.1")
	}))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), "192.168.178.11")
	}))
}

func TestMergeURISingles(t *testing.T) {
	ast := assert.New(t)

	uri, err := url.Parse("host.Local")
	ast.Nil(err)
	crt := make(map[string]any)
	crt["uri"] = uri.String()
	uris, err := mergeURIs(crt, nil)
	ast.Nil(err)
	ast.Equal(1, len(uris))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), uri.String())
	}))
	u1, _ := url.Parse("localhost")
	uris, err = mergeURIs(nil, []*url.URL{u1, uri})
	ast.Nil(err)
	ast.Equal(2, len(uris))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), uri.String())
	}))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), u1.String())
	}))
}

func TestMergeURISimple(t *testing.T) {
	ast := assert.New(t)

	uri, err := url.Parse("host.Local")
	ast.Nil(err)
	crt := make(map[string]any)
	crt["uri"] = uri.String()
	u1, _ := url.Parse("localhost")
	u2, _ := url.Parse("www.mcs.de")
	uris, err := mergeURIs(crt, []*url.URL{u1, u2})
	ast.Nil(err)
	ast.Equal(3, len(uris))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), uri.String())
	}))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), "localhost")
	}))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), "www.mcs.de")
	}))
}

func TestMergeURIDoublets(t *testing.T) {
	ast := assert.New(t)

	uri, err := url.Parse("host.Local")
	ast.Nil(err)

	crt := make(map[string]any)
	crt["uri"] = uri.String()
	u1, _ := url.Parse("localhost")
	u2, _ := url.Parse("www.mcs.de")
	uris, err := mergeURIs(crt, []*url.URL{u1, u2, uri})
	ast.Nil(err)
	ast.Equal(3, len(uris))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), uri.String())
	}))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), "localhost")
	}))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), "www.mcs.de")
	}))
}

func TestMergeURIList(t *testing.T) {
	ast := assert.New(t)

	uri, err := url.Parse("host.Local")
	ast.Nil(err)

	crt := make(map[string]any)
	crt["uri"] = []string{uri.String()}
	u1, _ := url.Parse("localhost")
	u2, _ := url.Parse("www.mcs.de")
	uris, err := mergeURIs(crt, []*url.URL{u1, u2, uri})
	ast.Nil(err)
	ast.Equal(3, len(uris))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), uri.String())
	}))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), "localhost")
	}))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), "www.mcs.de")
	}))
}

func TestMergeURIListInterface(t *testing.T) {
	ast := assert.New(t)

	uri, err := url.Parse("host.Local")
	ast.Nil(err)

	crt := make(map[string]any)
	crt["uri"] = []interface{}{"localhost", *uri}
	u1, _ := url.Parse("localhost")
	u2, _ := url.Parse("www.mcs.de")
	uris, err := mergeURIs(crt, []*url.URL{u1, u2})
	ast.Nil(err)
	ast.Equal(3, len(uris))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), uri.String())
	}))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), "localhost")
	}))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), "www.mcs.de")
	}))
}
