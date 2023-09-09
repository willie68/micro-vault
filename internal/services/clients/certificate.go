package clients

import (
	"crypto/x509"
	"net"
	"net/url"
	"strings"

	"slices"
)

func mergeListWCRTValue(source []string, crtValue any, appendValue bool) []string {
	if ((len(source) == 0) || appendValue) && (crtValue != nil) {
		if source == nil {
			source = make([]string, 0)
		}
		return append(source, crtValue.(string))
	}
	return source
}

func mergeTemplate(tmp *x509.CertificateRequest, crt map[string]any) (*x509.CertificateRequest, error) {
	if tmp.Subject.CommonName == "" {
		tmp.Subject.CommonName = crt["ucn"].(string)
	}
	tmp.Subject.Country = mergeListWCRTValue(tmp.Subject.Country, crt["uco"], false)
	tmp.Subject.Province = mergeListWCRTValue(tmp.Subject.Province, crt["upr"], false)
	tmp.Subject.Locality = mergeListWCRTValue(tmp.Subject.Locality, crt["ulo"], false)
	tmp.Subject.Organization = mergeListWCRTValue(tmp.Subject.Organization, crt["uor"], false)
	tmp.Subject.OrganizationalUnit = mergeListWCRTValue(tmp.Subject.OrganizationalUnit, crt["uou"], false)
	tmp.Subject.StreetAddress = mergeListWCRTValue(tmp.Subject.StreetAddress, crt["usa"], false)
	tmp.Subject.PostalCode = mergeListWCRTValue(tmp.Subject.PostalCode, crt["upc"], false)

	tmp.EmailAddresses = mergeListWCRTValue(tmp.EmailAddresses, crt["uem"], true)

	var err error
	tmp.DNSNames, err = mergeDNSs(crt, tmp.DNSNames)
	if err != nil {
		return nil, err
	}

	tmp.IPAddresses, err = mergeIPs(crt, tmp.IPAddresses)
	if err != nil {
		return nil, err
	}

	tmp.URIs, err = mergeURIs(crt, tmp.URIs)
	if err != nil {
		return nil, err
	}
	return tmp, nil
}

func mergeDNSs(crt map[string]any, tmpDNSs []string) ([]string, error) {
	dnss := make([]string, 0)
	if tmpDNSs != nil {
		dnss = append(dnss, tmpDNSs...)
	}
	if crt["dns"] != nil {
		switch v := crt["dns"].(type) {
		case string:
			dnss = append(dnss, v)
		case []string:
			dnss = append(dnss, v...)
		case []any:
			for _, mv := range v {
				dns, ok := mv.(string)
				if ok {
					dnss = append(dnss, dns)
				}
			}
		}
		slices.Sort(dnss)
		dnss = slices.Compact(dnss)
	}
	return dnss, nil
}

func mergeIPs(crt map[string]any, tmpIPs []net.IP) ([]net.IP, error) {
	ips := make([]net.IP, 0)
	if tmpIPs != nil {
		ips = append(ips, tmpIPs...)
	}
	if crt["ip"] != nil {
		ipsv, err := buildIPList(crt["ip"])
		if err != nil {
			return nil, err
		}
		ips = append(ips, ipsv...)
		slices.SortFunc(ips, func(a, b net.IP) int {
			return strings.Compare(a.String(), b.String())
		})
		return slices.CompactFunc(ips, func(e1, e2 net.IP) bool {
			return e1.Equal(e2)
		}), nil
	}
	return ips, nil
}

func buildIPList(crtIPs any) ([]net.IP, error) {
	ips := make([]net.IP, 0)
	switch v := crtIPs.(type) {
	case string:
		ip := net.ParseIP(v)
		ips = append(ips, ip)
	case []string:
		for _, mv := range v {
			ip := net.ParseIP(mv)
			ips = append(ips, ip)
		}
	case []any:
		for _, mv := range v {
			switch mvv := mv.(type) {
			case string:
				ip := net.ParseIP(mvv)
				ips = append(ips, ip)
			case net.IP:
				ips = append(ips, mvv)
			}
		}
	}
	return ips, nil
}

func mergeURIs(crt map[string]any, tmpURIs []*url.URL) ([]*url.URL, error) {
	uris := make([]*url.URL, 0)
	if tmpURIs != nil {
		uris = append(uris, tmpURIs...)
	}
	if crt["uri"] != nil {
		u, err := buildURIList(crt["uri"])
		if err != nil {
			return nil, err
		}
		uris = append(uris, u...)
		slices.SortFunc(uris, func(a, b *url.URL) int {
			return strings.Compare(a.String(), b.String())
		})
		return slices.CompactFunc(uris, func(e1, e2 *url.URL) bool {
			return e1.String() == e2.String()
		}), nil
	}
	return uris, nil
}

func buildURIList(crtUris any) ([]*url.URL, error) {
	uris := make([]*url.URL, 0)
	switch v := crtUris.(type) {
	case string:
		ul, err := url.Parse(v)
		if err != nil {
			return nil, err
		}
		uris = append(uris, ul)
	case []string:
		luris, err := stringsToURLList(v)
		if err != nil {
			return nil, err
		}
		uris = append(uris, luris...)
	case []any:
		luris, err := anyToURLList(v)
		if err != nil {
			return nil, err
		}
		uris = append(uris, luris...)
	}
	return uris, nil
}

func stringsToURLList(v []string) ([]*url.URL, error) {
	uris := make([]*url.URL, 0)
	for _, mv := range v {
		ul, err := url.Parse(mv)
		if err != nil {
			return nil, err
		}
		uris = append(uris, ul)
	}
	return uris, nil
}

func anyToURLList(v []any) ([]*url.URL, error) {
	uris := make([]*url.URL, 0)
	for _, mv := range v {
		switch mvv := mv.(type) {
		case string:
			ul, err := url.Parse(mvv)
			if err != nil {
				return nil, err
			}
			uris = append(uris, ul)
		case url.URL:
			uris = append(uris, &mvv)
		}
	}
	return uris, nil
}
