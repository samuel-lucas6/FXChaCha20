using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using Geralt;

namespace FXChaCha20DotNet.Benchmarks;

[Config(typeof(Configuration))]
public class Program
{
    private readonly byte[] _ciphertext = new byte[ChaCha20.BlockSize];
    private readonly byte[] _plaintext = new byte[ChaCha20.BlockSize];
    private readonly byte[] _nonce = new byte[ChaCha20.NonceSize];
    private readonly byte[] _xNonce = new byte[XChaCha20.NonceSize];
    private readonly byte[] _xxNonce = new byte[FXXChaCha20.NonceSize];
    private readonly byte[] _key = new byte[ChaCha20.KeySize];

    [GlobalSetup]
    public void Setup()
    {
        RandomNumberGenerator.Fill(_plaintext);
        RandomNumberGenerator.Fill(_nonce);
        RandomNumberGenerator.Fill(_xNonce);
        RandomNumberGenerator.Fill(_xxNonce);
        RandomNumberGenerator.Fill(_key);
    }

    [Benchmark(Description = "XChaCha20 (implementation)", Baseline = true)]
    public void RunXChaCha20Implementation()
    {
        ExtendedChaCha20.Encrypt(_ciphertext, _plaintext, _xNonce, _key);
    }

    [Benchmark(Description = "ChaCha20")]
    public void RunChaCha20()
    {
        ChaCha20.Encrypt(_ciphertext, _plaintext, _nonce, _key);
    }

    [Benchmark(Description = "XChaCha20")]
    public void RunXChaCha20()
    {
        XChaCha20.Encrypt(_ciphertext, _plaintext, _xNonce, _key);
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

    static void Main(string[] args)
    {
        BenchmarkRunner.Run<Program>();
    }
}
