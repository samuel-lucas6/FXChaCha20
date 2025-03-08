using System.Security.Cryptography;
using static Monocypher.Monocypher;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using Geralt;

namespace FXChaCha20DotNet.Benchmarks;

[Config(typeof(Configuration))]
public class Program
{
    private readonly byte[] _ciphertext = new byte[ChaCha20.BlockSize / 2];
    private readonly byte[] _plaintext = new byte[ChaCha20.BlockSize / 2];
    private readonly byte[] _nonce = new byte[ChaCha20.NonceSize];
    private readonly byte[] _hNonce = new byte[HChaCha20.NonceSize];
    private readonly byte[] _xNonce = new byte[XChaCha20.NonceSize];
    private readonly byte[] _xxNonce = new byte[FXXChaCha20.NonceSize];
    private readonly byte[] _key = new byte[ChaCha20.KeySize];

    [GlobalSetup]
    public void Setup()
    {
        RandomNumberGenerator.Fill(_plaintext);
        RandomNumberGenerator.Fill(_nonce);
        RandomNumberGenerator.Fill(_hNonce);
        RandomNumberGenerator.Fill(_xNonce);
        RandomNumberGenerator.Fill(_xxNonce);
        RandomNumberGenerator.Fill(_key);
    }

    [Benchmark(Description = "XChaCha20 (implementation)", Baseline = true)]
    public void RunXChaCha20Implementation()
    {
        ExtendedChaCha20.Encrypt(_ciphertext, _plaintext, _xNonce, _key);
    }

    [Benchmark(Description = "FXChaCha20")]
    public void RunFXChaCha20()
    {
        FXChaCha20.Encrypt(_ciphertext, _plaintext, _xNonce, _key);
    }

    [Benchmark(Description = "FXXChaCha20")]
    public void RunFXXChaCha20()
    {
        FXXChaCha20.Encrypt(_ciphertext, _plaintext, _xxNonce, _key);
    }

    [Benchmark(Description = "ChaCha20 (libsodium)")]
    public void RunChaCha20Libsodium()
    {
        ChaCha20.Encrypt(_ciphertext, _plaintext, _nonce, _key);
    }

    [Benchmark(Description = "XChaCha20 (libsodium)")]
    public void RunXChaCha20Libsodium()
    {
        XChaCha20.Encrypt(_ciphertext, _plaintext, _xNonce, _key);
    }

    [Benchmark(Description = "HChaCha20 (libsodium)")]
    public void RunHChaCha20Libsodium()
    {
        HChaCha20.DeriveKey(_key, _key, _hNonce);
    }

    [Benchmark(Description = "ChaCha20 (Monocypher)")]
    public void RunChaCha20Monocypher()
    {
        crypto_chacha20_ietf(_ciphertext, _plaintext, _key, _nonce, ctr: 0);
    }

    [Benchmark(Description = "XChaCha20 (Monocypher)")]
    public void RunXChaCha20Monocypher()
    {
        crypto_chacha20_x(_ciphertext, _plaintext, _key, _xNonce, ctr: 0);
    }

    [Benchmark(Description = "HChaCha20 (Monocypher)")]
    public void RunHChaCha20Monocypher()
    {
        crypto_chacha20_h(_key, _key, _hNonce);
    }

    static void Main(string[] args)
    {
        BenchmarkRunner.Run<Program>();
    }
}
