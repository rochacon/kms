package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

var VERSION = "dev"

func main() {
	flag.Parse()
	if flag.NArg() < 1 {
		usage()
	}
	var err error
	switch flag.Arg(0) {
	case "decrypt":
		err = decrypt(os.Stdin, os.Stdout)
	case "encrypt":
		keyId := flag.Arg(1)
		err = encrypt(keyId, os.Stdin, os.Stdout)
	case "version":
		fmt.Printf("kms %s\n", VERSION)
	default:
		usage()
	}
	if err != nil {
		log.Fatalf("failed: %s\n", err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "kms is an utility tool to encrypt and decrypt content using AWS KMS service.\n\n")
	fmt.Fprintf(os.Stderr, "All data must be provided via stdin, stdout will be used for the content and stderr for info\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  kms decrypt < encrypted.kms > plaintext\n")
	fmt.Fprintf(os.Stderr, "  kms encrypt alias/some-key-alias < plaintext > encrypted.kms\n")
	fmt.Fprintf(os.Stderr, "  kms encrypt 01234567-8901-2345-6789-012345678901 < plaintext > encrypted.kms\n")
	fmt.Fprintf(os.Stderr, "  kms version\n")
	os.Exit(1)
}

func decrypt(in io.Reader, out io.Writer) error {
	kmsSvc := kms.New(session.Must(session.NewSession()))
	blob, _ := ioutil.ReadAll(in)
	resp, err := kmsSvc.Decrypt(&kms.DecryptInput{
		CiphertextBlob: blob,
	})
	if err != nil {
		return fmt.Errorf("kms:Decrypt call failed: %w", err)
	}
	_, err = out.Write(resp.Plaintext)
	if err != nil {
		return fmt.Errorf("failed writing plaintext data: %w", err)
	}
	return nil
}

func encrypt(keyId string, in io.Reader, out io.Writer) error {
	kmsSvc := kms.New(session.Must(session.NewSession()))
	plaintext, _ := ioutil.ReadAll(in)
	resp, err := kmsSvc.Encrypt(&kms.EncryptInput{
		Plaintext: plaintext,
		KeyId:     aws.String(keyId),
	})
	if err != nil {
		return fmt.Errorf("kms:Encrypt call failed: %w", err)
	}
	_, err = out.Write(resp.CiphertextBlob)
	if err != nil {
		return fmt.Errorf("failed writing ciphertext data: %w", err)
	}
	return nil
}
