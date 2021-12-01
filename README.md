# Golang module for generating access token in Github token format

This Golang module creates an access token in the format of `prefix``separator``code``crc32 checksum`
as is being done by GitHub.

The generated token can be used for purposes aside access. You can distinguish tokens using their prefixes within your own applications.

The token can be verified to be untampered if the checksum matches the code. This is meant to verify a token is valid before any checks in the database is made.


## Usage

```go

const (
    prefix = "abc"
    randomBytesLen = 32
)

token, err:= accesstoken.Generate(prefix, accesstoken.Separator, accesstoken.RandomBytesLen)
if nil != err {
    return
}

if !accesstoken.IsChecksumOK(prefix, accesstoken.Separator) {
    return
}

fmt.Println("token is ok")

```