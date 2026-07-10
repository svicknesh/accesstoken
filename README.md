# Golang module for generating access tokens in GitHub token format

This Golang module creates an access token in the format `prefix` + `separator` + `code`,
where `code` is a base62-encoded combination of random bytes and a CRC-32 checksum, similar
to the format used by GitHub.

The generated token can be used for purposes other than access control. You can distinguish
token types using their prefixes within your own applications.

## Security properties and limitations

`IsChecksumOK` only reports whether a token is **well-formed** — that its embedded checksum
matches its embedded random bytes. This is a non-cryptographic CRC-32 checksum: it detects
accidental corruption (e.g. a copy/paste error or a dropped character), but it provides
**no tamper resistance and no authenticity guarantee**. There is no secret key involved, so
anyone who knows the algorithm can construct a token with a valid-looking checksum.

A `true` result from `IsChecksumOK` must **not** be treated as proof that:

- the token was issued by your system,
- the token is still valid, unexpired, or unrevoked, or
- the caller is authorized.

Use `IsChecksumOK` only as a cheap, early rejection of malformed input (e.g. to avoid an
unnecessary database round trip for a clearly garbled token). Always perform the real
authorization decision — a database or cache lookup that checks issuance, expiry, and
revocation status — before granting access.

`IsChecksumOK` never panics: malformed, truncated, or otherwise invalid input returns `false`.

## Usage

```go
const (
    prefix         = "abc"
    randomBytesLen = 32
)

token, err := accesstoken.Generate(prefix, accesstoken.Separator, accesstoken.RandomBytesLen)
if err != nil {
    return err
}

if !accesstoken.IsChecksumOK(prefix, accesstoken.Separator, token) {
    // token is malformed; reject before any database lookup
    return
}

// token is well-formed: proceed to look it up (and check expiry/revocation) in your database
```
