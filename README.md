# FXChaCha20: Feed-forward XChaCha20
FXChaCha20 and FXXChaCha20 represent another way to do [XChaCha20](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha) and [XXChaCha20](https://github.com/samuel-lucas6/XXChaCha20), respectively. They have the following advantages:

- HChaCha20 is not required, just ChaCha20.
- FXChaCha20 can be implemented with any ChaCha20 API compliant with the [RFC](https://www.rfc-editor.org/rfc/rfc8439).
- The performance may be better in some cases.
- Various security analyses from papers only discuss ChaCha20 with the feed-forward (e.g., for [AEAD commitment](https://eprint.iacr.org/2025/222)).

The downsides are:

- HChaCha20 should be faster because it does fewer operations.
- HChaCha20 offers better domain separation from ChaCha20 for encryption.
- The internal counter is only 32 bits when [some](https://doc.libsodium.org/advanced/stream_ciphers/xchacha20) XChaCha20 implementations support a 64-bit counter.
- FXXChaCha20 needs a ChaCha20 API that exposes the [internal counter](https://monocypher.org/manual/chacha20) for the nonce extension.

However, the subkey and a random nonce offer sufficient domain separation, and there should be very few real-world use cases for a counter larger than 32 bits (e.g., due to [stream encryption](https://eprint.iacr.org/2015/189)).

## Design
### FXChaCha20
```
subkey = ChaCha20(key, nonce[0..12], allZeros)

ciphertext = ChaCha20(subkey, nonce[12..24], plaintext)
```

### FXXChaCha20
```
subkey = ChaCha20(key, nonce[4..16], allZeros, counter: ReadLE32(nonce[0..4]))

ciphertext = ChaCha20(subkey, nonce[16..28], plaintext)
```

## Benchmarks
```
BenchmarkDotNet v0.14.0, Windows 11 (10.0.22631.4890/23H2/2023Update/SunValley3)

Intel Core i5-9600K CPU 3.70GHz (Coffee Lake), 1 CPU, 6 logical and 6 physical cores

.NET SDK 8.0.406
  [Host]     : .NET 8.0.13 (8.0.1325.6609), X64 RyuJIT AVX2
  DefaultJob : .NET 8.0.13 (8.0.1325.6609), X64 RyuJIT AVX2
```

Encrypting 32 bytes/deriving a 256-bit subkey (half a ChaCha20 block):

| Method                 |      Mean |    Error |   StdDev |        Ratio | RatioSD |
| ---------------------- | --------: | -------: | -------: | -----------: | ------: |
| XChaCha20              | 255.68 ns | 3.420 ns | 2.856 ns |     baseline |         |
| FXChaCha20             | 246.56 ns | 0.242 ns | 0.202 ns | 1.04x faster |   0.01x |
| FXXChaCha20            | 251.62 ns | 0.120 ns | 0.106 ns | 1.02x faster |   0.01x |
| HChaCha20 (libsodium)  |  96.32 ns | 0.040 ns | 0.036 ns | 2.65x faster |   0.03x |
| ChaCha20 (libsodium)   | 103.26 ns | 0.050 ns | 0.042 ns | 2.48x faster |   0.03x |
| XChaCha20 (libsodium)  | 191.22 ns | 0.151 ns | 0.142 ns | 1.34x faster |   0.01x |
| HChaCha20 (Monocypher) | 183.88 ns | 0.097 ns | 0.091 ns | 1.39x faster |   0.01x |
| ChaCha20 (Monocypher)  | 230.68 ns | 0.214 ns | 0.189 ns | 1.11x faster |   0.01x |
| XChaCha20 (Monocypher) | 417.26 ns | 0.188 ns | 0.166 ns | 1.63x slower |   0.02x |

The motivation for this project was actually the observation that HChaCha20 appeared [slower](https://github.com/samuel-lucas6/hchachacha) than ChaCha20 with a 256-bit output in a benchmark.

However, HChaCha20 is faster than ChaCha20 in both libsodium and Monocypher, which seems to contradict the original observation and aligns with common sense since HChaCha20 performs fewer operations.

When implementing XChaCha20 using separate HChaCha20 and ChaCha20 APIs (to account for overhead from [Geralt](https://www.geralt.xyz/)/C#), FXChaCha20 and FXXChaCha20 were marginally faster, but this is likely due to fewer allocations/less copying. If you eliminated the zero prefix to the nonce, XChaCha20 would likely be faster.
