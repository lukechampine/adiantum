adiantum
--------

[![GoDoc](https://godoc.org/lukechampine.com/adiantum?status.svg)](https://godoc.org/lukechampine.com/adiantum)
[![Go Report Card](http://goreportcard.com/badge/lukechampine.com/adiantum)](https://goreportcard.com/report/lukechampine.com/adiantum)

```
go get lukechampine.com/adiantum/adiantum/...
```

This repo contains an implementation of [HBSH](https://eprint.iacr.org/2018/720.pdf), a tweakable and length-preserving
encryption mode. These properties make HBSH a good choice for disk encryption.
Furthermore, HBSH is a "super-pseudorandom permutation", meaning that changing a
single bit of the plaintext scrambles the entire ciphertext; this is in contrast
to the most common disk encryption mode, XTS, where one bitflip scrambles only
16 bytes of the ciphertext.

HBSH is a construction, not a primitive. Specifically, it is built from a stream
cipher, a block cipher, and a hash function. The original paper provides a proof
that this construction is secure if the underlying primitives are secure.

Adiantum is a form of HBSH that uses XChaCha12 for the stream cipher, AES for
the block cipher, and NH and Poly1305 for hashing. This is the variant that the
paper recommends for most uses. The paper also describes HPolyC, which is slower
on large messages, but more key-agile and simpler to implement.

This repo currently contains only an implementation of HPolyC-XChaCha20-AES.
This variant was chosen because it was the simplest to implement using existing
Go crypto packages. An Adiantum implementation is planned. (The repo is named
`adiantum` to match the name used by the original paper and [repository](https://github.com/google/adiantum).)


## Usage

```go
import "lukechampine.com/adiantum/hpolyc"

func main() {
    var hpc hpolyc.HPolyC
    key := make([]byte, 32) // in practice, read this from crypto/rand
    tweak := make([]byte, 12) // can be any length
    plaintext := []byte("Hello, world!")
    ciphertext := hpc.Encrypt(plaintext, key, tweak)
    recovered := hpc.Decrypt(ciphertext, key, tweak)
    println(string(recovered)) // Hello, world!
}
```

To use HBSH for disk encryption, simply set the tweak equal to the disk sector
index. For example, to encrypt *n* consecutive 4096-byte sectors, increment the
tweak by 1 after encrypting the each sector.

It is important to understand the threat model for disk encryption.
Specifically, disk encryption is most effective when the attacker only sees one
version of the disk contents. It is less effective when the attacker can sample
the contents at will. This is because writing the same sector to the same
location will result in the same ciphertext. As such, an attacker with multiple
samples can detect if you "undo" a disk write by overwriting a sector with a
previous version of that sector. Worse, an attacker can replace a sector with a
previously-written sector, and it will decrypt just fine. [See
here](https://sockpuppet.org/blog/2014/04/30/you-dont-want-xts/) for a more
detailed critique of disk encryption and some recommended alternatives.


## Benchmarks

The paper gives a figure of 17.8 cycles per byte for HPolyC-XChaCha20-AES for a
4096-byte sector. On a 1GHz CPU, this translates to about 56 MB/s. On my 3.8GHz
i7, this package achieves 322 MB/s, a 50% improvement. I'm not sure what
accounts for this disparity, but I imagine it is largely because the authors
tested on ARM rather than amd64.

```
BenchmarkHPolyC/Encrypt-4    100000    12719 ns/op    322.04 MB/s    0 allocs/op
BenchmarkHPolyC/Decrypt-4    100000    12929 ns/op    316.79 MB/s    0 allocs/op
```
