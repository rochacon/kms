`kms` is an utility tool to encrypt and decrypt content using AWS KMS service.

[![build](https://github.com/rochacon/kms/workflows/build/badge.svg)](https://github.com/rochacon/kms/actions?query=workflow%3Abuild)

### Usage

```
kms is an utility tool to encrypt and decrypt content using AWS KMS service.

All data must be provided via stdin, stdout will be used for the content and stderr for info

Usage:
  kms decrypt < encrypted.kms > plaintext
  kms encrypt alias/some-key-alias < plaintext > encrypted.kms
  kms encrypt 01234567-8901-2345-6789-012345678901 < plaintext > encrypted.kms
```
