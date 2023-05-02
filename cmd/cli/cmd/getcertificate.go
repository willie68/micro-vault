/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/willie68/micro-vault/cmd/cli/cmd/cmdutils"
)

// getCertificateCmd represents the certificate command
var getCertificateCmd = &cobra.Command{
	Use:   "certificate",
	Short: "get a signed certificate from the mv ca",
	Long:  `get a signed certificate from the mv ca`,
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
		template := x509.CertificateRequest{
			RawSubject:     asn1Subj,
			EmailAddresses: []string{emailAddress},
		}

		cert, err := cli.Certificate(template)
		if err != nil {
			return err
		}
		p, err := cli.PrivateKey()
		if err != nil {
			return err
		}
		err = outputCertificate(*cert, *p, filepath.Join(o, "cert.pem"), filepath.Join(o, "key.pem"))
		if err != nil {
			return err
		}
		return nil
	},
}

func init() {
	getCmd.AddCommand(getCertificateCmd)
	getCertificateCmd.Flags().StringP("outputPath", "o", "./", "where to put the files")

	getCertificateCmd.Flags().String("ucn", "", "insert the common name")
	getCertificateCmd.Flags().String("uco", "", "insert the country")
	getCertificateCmd.Flags().String("upr", "", "insert the province")
	getCertificateCmd.Flags().String("ulo", "", "insert the locality")
	getCertificateCmd.Flags().String("uor", "", "insert the organisation")
	getCertificateCmd.Flags().String("uou", "", "insert the organisation unit")
	getCertificateCmd.Flags().String("usa", "", "insert the street address")
	getCertificateCmd.Flags().String("upc", "", "insert the postal code")
	getCertificateCmd.Flags().String("uem", "", "insert the email")
}

func outputCertificate(c x509.Certificate, p rsa.PrivateKey, certFile, privFile string) error {
	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
		return err
	}
	if err := certOut.Close(); err != nil {
		return err
	}
	log.Print("wrote cert.pem\n")

	keyOut, err := os.OpenFile(privFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(&p)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}
	if err := keyOut.Close(); err != nil {
		return err
	}
	log.Print("wrote key.pem\n")
	return nil
}
