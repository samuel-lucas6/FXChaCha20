namespace FXChaCha20DotNet.Tests;

[TestClass]
public class FXXChaCha20Tests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "dd956b32e6600f91e88a4d81b737404f9a18553777841417c2420dc369bd3eddfc64a93c46e383f01aa94e5e9187ecc5ad02efff46a16e4d6c03562f6d26d8f6bdb684832bf31353485a04f22e055d3a9ce2ad3f76870d03fba1e3b506113cd0239146090bf09dd91b2f4082405605a58e6796927667ea74704ec0a93c351844f2ab49c1ceffc240dbd2fe5bb8482ef4ad00d3a1b322bba474c8e01f27a691747f2d2493226283881b795ef7bea9ba80d19b3ac290e6903a0fab941f07879c94213bb747ce3206b8718e480c7409ec67b8ace6e2995799074ecf95064777ddd75f7c17158f75fa5e6899a8744d504636e75363e9ee3f458e33457953b7f3a4c91ac1b5bebc0a1c2252a4cb186055a27755beeb69c2c842586276fe13cb8fd98ec5e1db666317a6dd81172d92ef88c795",
            "5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e",
            "404142434445464748494a4b4c4d4e4f505152535455565758596061",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            (uint)0
        ];
        yield return
        [
            "8db1868f6fe9195b0d1e43e5704a523b8dacb9327bd45b0bfda3e1b74b5e328d23b95e5a0da3d6d616375bd601514db4c671dfa9602ee466394cc099302b1105f8e45d858bfdcf4189d2b15ee11c6ff6a64fcfbafa3ca0ba7886eb5628acd63b7f083fdd2c3ccf8c1e714ee7bebbbd9ddfc807d09cb5df3446addc341bd594993a68ad59ce620fb367ca1b056811a06eb3e3e7e4d44a93070b868a4f4f7e9cc50c791e128d3cb64c668aa5301a594538ac001ba1e4231c892e476213eeb9a0c604d3b0bbf50a1c2252a4de1c715cbd3258f0a168c7dd075e2367e25dc78ed19e96eedc626f1fff8aab022bdbfc86cecd7f5d8d182a3c4b0a53ef8e4ab3095016154ad273d450555df16c74b82b10b7ac248296cb01afd0d1d131a5c80da2e561848d17c788ced169596e87fcb2b72527",
            "5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e",
            "404142434445464748494a4b4c4d4e4f505152535455565758596061",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            (uint)1
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [FXXChaCha20.BlockSize + 1, FXXChaCha20.BlockSize, FXXChaCha20.NonceSize, FXXChaCha20.KeySize, (uint)0];
        yield return [FXXChaCha20.BlockSize - 1, FXXChaCha20.BlockSize, FXXChaCha20.NonceSize, FXXChaCha20.KeySize, (uint)0];
        yield return [FXXChaCha20.BlockSize, FXXChaCha20.BlockSize, FXXChaCha20.NonceSize + 1, FXXChaCha20.KeySize, (uint)0];
        yield return [FXXChaCha20.BlockSize, FXXChaCha20.BlockSize, FXXChaCha20.NonceSize - 1, FXXChaCha20.KeySize, (uint)0];
        yield return [FXXChaCha20.BlockSize, FXXChaCha20.BlockSize, FXXChaCha20.NonceSize, FXXChaCha20.KeySize + 1, (uint)0];
        yield return [FXXChaCha20.BlockSize, FXXChaCha20.BlockSize, FXXChaCha20.NonceSize, FXXChaCha20.KeySize - 1, (uint)0];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, FXXChaCha20.KeySize);
        Assert.AreEqual(28, FXXChaCha20.NonceSize);
        Assert.AreEqual(64, FXXChaCha20.BlockSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, uint counter)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);

        FXXChaCha20.Encrypt(c, p, n, k, counter);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, uint counter)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => FXXChaCha20.Encrypt(c, p, n, k, counter));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, uint counter)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);

        FXXChaCha20.Decrypt(p, c, n, k, counter);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, uint counter)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => FXXChaCha20.Decrypt(p, c, n, k, counter));
    }
}
