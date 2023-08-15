package clients

import (
	"crypto/x509"
	"net"
	"net/url"
	"strings"

	"slices"
)

func mergeTemplate(tmp *x509.CertificateRequest, crt map[string]any) (*x509.CertificateRequest, error) {
	if tmp.Subject.CommonName == "" {
		tmp.Subject.CommonName = crt["ucn"].(string)
	}
	if (len(tmp.Subject.Country) == 0) && (crt["uco"] != nil) {
		if tmp.Subject.Country == nil {
			tmp.Subject.Country = make([]string, 0)
		}
		tmp.Subject.Country = append(tmp.Subject.Country, crt["uco"].(string))
	}
	if (len(tmp.Subject.Province) == 0) && (crt["upr"] != nil) {
		if tmp.Subject.Province == nil {
			tmp.Subject.Province = make([]string, 0)
		}
		tmp.Subject.Province = append(tmp.Subject.Province, crt["upr"].(string))
	}
	if (len(tmp.Subject.Locality) == 0) && (crt["ulo"] != nil) {
		if tmp.Subject.Locality == nil {
			tmp.Subject.Locality = make([]string, 0)
		}
		tmp.Subject.Locality = append(tmp.Subject.Locality, crt["ulo"].(string))
	}
	if (len(tmp.Subject.Organization) == 0) && (crt["uor"] != nil) {
		if tmp.Subject.Organization == nil {
			tmp.Subject.Organization = make([]string, 0)
		}
		tmp.Subject.Organization = append(tmp.Subject.Organization, crt["uor"].(string))
	}
	if (len(tmp.Subject.OrganizationalUnit) == 0) && (crt["uou"] != nil) {
		if tmp.Subject.OrganizationalUnit == nil {
			tmp.Subject.OrganizationalUnit = make([]string, 0)
		}
		tmp.Subject.OrganizationalUnit = append(tmp.Subject.OrganizationalUnit, crt["uou"].(string))
	}
	if (len(tmp.Subject.StreetAddress) == 0) && (crt["usa"] != nil) {
		if tmp.Subject.StreetAddress == nil {
			tmp.Subject.StreetAddress = make([]string, 0)
		}
		tmp.Subject.StreetAddress = append(tmp.Subject.StreetAddress, crt["usa"].(string))
	}
	if (len(tmp.Subject.PostalCode) == 0) && (crt["upc"] != nil) {
		if tmp.Subject.PostalCode == nil {
			tmp.Subject.PostalCode = make([]string, 0)
		}
		tmp.Subject.PostalCode = append(tmp.Subject.PostalCode, crt["upc"].(string))
	}

	if crt["uem"] != nil {
		if tmp.EmailAddresses == nil {
			tmp.EmailAddresses = make([]string, 0)
		}
		tmp.EmailAddresses = append(tmp.EmailAddresses, crt["uem"].(string))
	}

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
		for _, mv := range v {
			ul, err := url.Parse(mv)
			if err != nil {
				return nil, err
			}
			uris = append(uris, ul)
		}
	case []any:
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
	}
	return uris, nil
}
