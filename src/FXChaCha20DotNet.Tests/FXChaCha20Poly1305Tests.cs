using System.Security.Cryptography;

namespace FXChaCha20DotNet.Tests;

[TestClass]
public class FXChaCha20Poly1305Tests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "65fce29e5d403c48a3b7d0cca3d627ca5eaf2ebc272f67884f5f60b1b5506c7f3a8a103c1db69096427b639b3e04d404287c116ea7f3d9f822715c1625b123d7547449a43e580cc291d93a4db16cff36b1ec01e757f8cb3e6c23258375489d59af38fed90ed2c498dd7995e892a6805d3f8a83ca9e0e27fdf269fcfe1c5b1a3ab4c6",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "404142434445464748494a4b4c4d4e4f5051525354555657",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [FXChaCha20Poly1305.TagSize - 1, 0, FXChaCha20Poly1305.NonceSize, FXChaCha20Poly1305.KeySize, FXChaCha20Poly1305.TagSize];
        yield return [FXChaCha20Poly1305.TagSize, 1, FXChaCha20Poly1305.NonceSize, FXChaCha20Poly1305.KeySize, FXChaCha20Poly1305.TagSize];
        yield return [FXChaCha20Poly1305.TagSize, 0, FXChaCha20Poly1305.NonceSize + 1, FXChaCha20Poly1305.KeySize, FXChaCha20Poly1305.TagSize];
        yield return [FXChaCha20Poly1305.TagSize, 0, FXChaCha20Poly1305.NonceSize - 1, FXChaCha20Poly1305.KeySize, FXChaCha20Poly1305.TagSize];
        yield return [FXChaCha20Poly1305.TagSize, 0, FXChaCha20Poly1305.NonceSize, FXChaCha20Poly1305.KeySize + 1, FXChaCha20Poly1305.TagSize];
        yield return [FXChaCha20Poly1305.TagSize, 0, FXChaCha20Poly1305.NonceSize, FXChaCha20Poly1305.KeySize - 1, FXChaCha20Poly1305.TagSize];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, FXChaCha20Poly1305.KeySize);
        Assert.AreEqual(24, FXChaCha20Poly1305.NonceSize);
        Assert.AreEqual(16, FXChaCha20Poly1305.TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        FXChaCha20Poly1305.Encrypt(c, p, n, k, ad);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => FXChaCha20Poly1305.Encrypt(c, p, n, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        FXChaCha20Poly1305.Decrypt(p, c, n, k, ad);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new Dictionary<string, byte[]>
        {
            { "c", Convert.FromHexString(ciphertext) },
            { "n", Convert.FromHexString(nonce) },
            { "k", Convert.FromHexString(key) },
            { "ad", Convert.FromHexString(associatedData) }
        };

        foreach (var param in parameters.Values.Where(param => param.Length > 0)) {
            param[0]++;
            Assert.ThrowsException<CryptographicException>(() => FXChaCha20Poly1305.Decrypt(p, parameters["c"], parameters["n"], parameters["k"], parameters["ad"]));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => FXChaCha20Poly1305.Decrypt(p, c, n, k, ad));
    }
}
