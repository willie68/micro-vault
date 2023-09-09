package clients

import (
	"crypto/x509"
	"net"
	"net/url"
	"strings"
	"testing"

	"slices"

	"github.com/stretchr/testify/assert"
)

const (
	hostDNS       = "willie.host"
	localHost     = "local.host"
	remoteHost    = "remote.host"
	homeIP        = "192.168.178.10"
	localIP       = "127.0.0.1"
	homeIP11      = "192.168.178.11"
	localHostName = "localhost"
	mcsHostName   = "www.mcs.de"
)

func TestMergeDNSSingles(t *testing.T) {
	ast := assert.New(t)

	crt := make(map[string]any)
	crt["dns"] = hostDNS
	dnss, err := mergeDNSs(crt, nil)
	ast.Nil(err)
	ast.Equal(1, len(dnss))
	ast.True(slices.Contains(dnss, hostDNS))

	dnss, err = mergeDNSs(nil, []string{localHost, remoteHost})
	ast.Nil(err)
	ast.Equal(2, len(dnss))
	ast.True(slices.Contains(dnss, remoteHost))
	ast.True(slices.Contains(dnss, localHost))
}

func TestMergeDNSSimple(t *testing.T) {
	ast := assert.New(t)

	crt := make(map[string]any)
	crt["dns"] = hostDNS
	dnss, err := mergeDNSs(crt, []string{localHost, remoteHost})
	ast.Nil(err)
	ast.Equal(3, len(dnss))
	ast.True(slices.Contains(dnss, hostDNS))
	ast.True(slices.Contains(dnss, remoteHost))
	ast.True(slices.Contains(dnss, localHost))
}

func TestMergeDNSDoublets(t *testing.T) {
	ast := assert.New(t)

	crt := make(map[string]any)
	crt["dns"] = hostDNS
	dnss, err := mergeDNSs(crt, []string{hostDNS, localHost, remoteHost})
	ast.Nil(err)
	ast.Equal(3, len(dnss))
	ast.True(slices.Contains(dnss, hostDNS))
	ast.True(slices.Contains(dnss, remoteHost))
	ast.True(slices.Contains(dnss, localHost))
}

func TestMergeDNSList(t *testing.T) {
	ast := assert.New(t)

	crt := make(map[string]any)
	crt["dns"] = []string{hostDNS}
	dnss, err := mergeDNSs(crt, []string{localHost, remoteHost})
	ast.Nil(err)
	ast.Equal(3, len(dnss))
	ast.True(slices.Contains(dnss, hostDNS))
	ast.True(slices.Contains(dnss, remoteHost))
	ast.True(slices.Contains(dnss, localHost))
}

func TestMergeDNSListInterface(t *testing.T) {
	ast := assert.New(t)

	crt := make(map[string]any)
	crt["dns"] = []any{hostDNS}
	dnss, err := mergeDNSs(crt, []string{localHost, remoteHost})
	ast.Nil(err)
	ast.Equal(3, len(dnss))
	ast.True(slices.Contains(dnss, hostDNS))
	ast.True(slices.Contains(dnss, remoteHost))
	ast.True(slices.Contains(dnss, localHost))
}

func TestMergeIPSingles(t *testing.T) {
	ast := assert.New(t)

	ip := net.ParseIP(homeIP)
	crt := make(map[string]any)
	crt["ip"] = ip.String()
	ips, err := mergeIPs(crt, nil)
	ast.Nil(err)
	ast.Equal(1, len(ips))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), ip.String())
	}))

	ips, err = mergeIPs(nil, []net.IP{net.ParseIP(localIP), ip})
	ast.Nil(err)
	ast.Equal(2, len(ips))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), ip.String())
	}))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), localIP)
	}))
}

func TestMergeIPSimple(t *testing.T) {
	ast := assert.New(t)

	ip := net.ParseIP(homeIP)
	crt := make(map[string]any)
	crt["ip"] = ip.String()
	ips, err := mergeIPs(crt, []net.IP{net.ParseIP(localIP), net.ParseIP(homeIP11)})
	ast.Nil(err)
	ast.Equal(3, len(ips))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), ip.String())
	}))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), localIP)
	}))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), homeIP11)
	}))
}

func TestMergeIPDoublets(t *testing.T) {
	ast := assert.New(t)

	ip := net.ParseIP(homeIP)

	crt := make(map[string]any)
	crt["ip"] = ip.String()
	ips, err := mergeIPs(crt, []net.IP{net.ParseIP(localIP), net.ParseIP(homeIP11), ip})
	ast.Nil(err)
	ast.Equal(3, len(ips))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), ip.String())
	}))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), localIP)
	}))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), homeIP11)
	}))
}

func TestMergeIPList(t *testing.T) {
	ast := assert.New(t)

	ip := net.ParseIP(homeIP)

	crt := make(map[string]any)
	crt["ip"] = []string{ip.String()}
	ips, err := mergeIPs(crt, []net.IP{net.ParseIP(localIP), net.ParseIP(homeIP11)})
	ast.Nil(err)
	ast.Equal(3, len(ips))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), ip.String())
	}))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), localIP)
	}))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), homeIP11)
	}))
}

func TestMergeIPListInterface(t *testing.T) {
	ast := assert.New(t)

	ip := net.ParseIP(homeIP)

	crt := make(map[string]any)
	crt["ip"] = []any{homeIP11, ip}
	ips, err := mergeIPs(crt, []net.IP{net.ParseIP(localIP), net.ParseIP(homeIP11)})
	ast.Nil(err)
	ast.Equal(3, len(ips))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), ip.String())
	}))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), localIP)
	}))
	ast.True(slices.ContainsFunc(ips, func(e net.IP) bool {
		return strings.EqualFold(e.String(), homeIP11)
	}))
}

func TestMergeURISingles(t *testing.T) {
	ast := assert.New(t)

	uri, err := url.Parse(localHost)
	ast.Nil(err)
	crt := make(map[string]any)
	crt["uri"] = uri.String()
	uris, err := mergeURIs(crt, nil)
	ast.Nil(err)
	ast.Equal(1, len(uris))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), uri.String())
	}))
	u1, _ := url.Parse(localHostName)
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

	uri, err := url.Parse(localHost)
	ast.Nil(err)
	crt := make(map[string]any)
	crt["uri"] = uri.String()
	u1, _ := url.Parse(localHostName)
	u2, _ := url.Parse(mcsHostName)
	uris, err := mergeURIs(crt, []*url.URL{u1, u2})
	ast.Nil(err)
	ast.Equal(3, len(uris))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), uri.String())
	}))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), localHostName)
	}))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), mcsHostName)
	}))
}

func TestMergeURIDoublets(t *testing.T) {
	ast := assert.New(t)

	uri, err := url.Parse(localHost)
	ast.Nil(err)

	crt := make(map[string]any)
	crt["uri"] = uri.String()
	u1, _ := url.Parse(localHostName)
	u2, _ := url.Parse(mcsHostName)
	uris, err := mergeURIs(crt, []*url.URL{u1, u2, uri})
	ast.Nil(err)
	ast.Equal(3, len(uris))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), uri.String())
	}))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), localHostName)
	}))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), mcsHostName)
	}))
}

func TestMergeURIList(t *testing.T) {
	ast := assert.New(t)

	uri, err := url.Parse(localHost)
	ast.Nil(err)

	crt := make(map[string]any)
	crt["uri"] = []string{uri.String()}
	u1, _ := url.Parse(localHostName)
	u2, _ := url.Parse(mcsHostName)
	uris, err := mergeURIs(crt, []*url.URL{u1, u2, uri})
	ast.Nil(err)
	ast.Equal(3, len(uris))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), uri.String())
	}))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), localHostName)
	}))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), mcsHostName)
	}))
}

func TestMergeURIListInterface(t *testing.T) {
	ast := assert.New(t)

	uri, err := url.Parse(localHost)
	ast.Nil(err)

	crt := make(map[string]any)
	crt["uri"] = []any{localHostName, *uri}
	u1, _ := url.Parse(localHostName)
	u2, _ := url.Parse(mcsHostName)
	uris, err := mergeURIs(crt, []*url.URL{u1, u2})
	ast.Nil(err)
	ast.Equal(3, len(uris))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), uri.String())
	}))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), localHostName)
	}))
	ast.True(slices.ContainsFunc(uris, func(e *url.URL) bool {
		return strings.EqualFold(e.String(), mcsHostName)
	}))
}

func TestMergeEmptyTemplate(t *testing.T) {
	ast := assert.New(t)

	tmp := &x509.CertificateRequest{}

	crt := make(map[string]any)
	crt["ucn"] = "common"
	crt["uco"] = "de"
	crt["upr"] = "province"
	crt["ulo"] = "locality"
	crt["uor"] = "organisation"
	crt["uou"] = "organisational-unit"
	crt["usa"] = "street"
	crt["uem"] = "email@test.com"
	crt["dns"] = []string{localHostName}
	crt["ip"] = []string{localIP}
	crt["uri"] = []string{"http://localhost.com"}

	tmp, err := mergeTemplate(tmp, crt)

	ast.Nil(err)
	ast.Equal("common", tmp.Subject.CommonName)
	ast.Equal("de", tmp.Subject.Country[0])
	ast.Equal("province", tmp.Subject.Province[0])
	ast.Equal("locality", tmp.Subject.Locality[0])
	ast.Equal("organisation", tmp.Subject.Organization[0])
	ast.Equal("organisational-unit", tmp.Subject.OrganizationalUnit[0])
	ast.Equal("street", tmp.Subject.StreetAddress[0])
	ast.Equal("email@test.com", tmp.EmailAddresses[0])
	ast.Equal(localHostName, tmp.DNSNames[0])
	ast.Equal(localIP, tmp.IPAddresses[0].String())
	ast.Equal("http://localhost.com", tmp.URIs[0].String())
}
