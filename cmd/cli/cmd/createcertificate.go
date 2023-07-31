/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"net/url"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/willie68/micro-vault/cmd/cli/cmd/cmdutils"
)

// createCertificateCmd represents the certificate command
var createCertificateCmd = &cobra.Command{
	Use:   "certificate",
	Short: "Create a signed certificate from the mv ca",
	Long:  `Create a signed certificate from the mv ca`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := cmdutils.Client()
		if err != nil {
			return err
		}
		o, err := cmd.Flags().GetString("outputPath")
		if err != nil {
			return err
		}
		uem, err := cmd.Flags().GetString("uem")
		if err != nil {
			return err
		}
		ucn, err := cmd.Flags().GetString("ucn")
		if err != nil {
			return err
		}
		uco, err := cmd.Flags().GetString("uco")
		if err != nil {
			return err
		}
		upr, err := cmd.Flags().GetString("upr")
		if err != nil {
			return err
		}
		ulo, err := cmd.Flags().GetString("ulo")
		if err != nil {
			return err
		}
		uor, err := cmd.Flags().GetString("uor")
		if err != nil {
			return err
		}
		uou, err := cmd.Flags().GetString("uou")
		if err != nil {
			return err
		}
		usa, err := cmd.Flags().GetString("usa")
		if err != nil {
			return err
		}
		upc, err := cmd.Flags().GetString("upc")
		if err != nil {
			return err
		}
		dnss, err := cmd.Flags().GetStringArray("dns")
		if err != nil {
			return err
		}
		ips, err := cmd.Flags().GetStringArray("ip")
		if err != nil {
			return err
		}
		uris, err := cmd.Flags().GetStringArray("uri")
		if err != nil {
			return err
		}

		emailAddress := uem
		subj := pkix.Name{
			CommonName:         ucn,
			Country:            []string{uco},
			Province:           []string{upr},
			Locality:           []string{ulo},
			Organization:       []string{uor},
			OrganizationalUnit: []string{uou},
			StreetAddress:      []string{usa},
			PostalCode:         []string{upc},
		}
		rawSubj := subj.ToRDNSequence()

		asn1Subj, err := asn1.Marshal(rawSubj)
		if err != nil {
			return err
		}

		netIps := []net.IP{}

		for _, ip := range ips {
			nip := net.ParseIP(ip)
			if nip == nil {
				return fmt.Errorf("ip format unparsable: %s", ip)
			}
			netIps = append(netIps, nip)
		}

		nuris := []*url.URL{}

		for _, uri := range uris {
			ul, err := url.Parse(uri)
			if err != nil {
				return fmt.Errorf("url format unparsable: %s", uri)
			}
			nuris = append(nuris, ul)
		}

		template := x509.CertificateRequest{
			RawSubject:     asn1Subj,
			EmailAddresses: []string{emailAddress},
			DNSNames:       dnss,
			IPAddresses:    netIps,
			URIs:           nuris,
		}

		cert, err := cli.CreateCertificate(template)
		if err != nil {
			return err
		}
		p, err := cli.PrivateKey()
		if err != nil {
			return err
		}
		err = cmdutils.OutputCertificate(*cert, *p, filepath.Join(o, "cert.pem"), filepath.Join(o, "key.pem"))
		if err != nil {
			return err
		}
		return nil
	},
}

func init() {
	createCmd.AddCommand(createCertificateCmd)
	createCertificateCmd.Flags().StringP("outputPath", "o", "./", "where to put the files")

	createCertificateCmd.Flags().String("ucn", "", "insert the common name")
	createCertificateCmd.Flags().String("uco", "", "insert the country")
	createCertificateCmd.Flags().String("upr", "", "insert the province")
	createCertificateCmd.Flags().String("ulo", "", "insert the locality")
	createCertificateCmd.Flags().String("uor", "", "insert the organisation")
	createCertificateCmd.Flags().String("uou", "", "insert the organisation unit")
	createCertificateCmd.Flags().String("usa", "", "insert the street address")
	createCertificateCmd.Flags().String("upc", "", "insert the postal code")
	createCertificateCmd.Flags().String("uem", "", "insert the email")
	createCertificateCmd.Flags().StringArray("dns", []string{}, "insert the dnsnames")
	createCertificateCmd.Flags().StringArray("ip", []string{}, "insert the ip addresses")
	createCertificateCmd.Flags().StringArray("uri", []string{}, "insert the uris")
}
