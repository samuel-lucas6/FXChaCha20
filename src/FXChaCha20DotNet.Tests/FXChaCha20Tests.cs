namespace FXChaCha20DotNet.Tests;

[TestClass]
public class FXChaCha20Tests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "1bece32e90aaeec9b00709e1878e6b8275e701f5481247282c01a0f7ca85527f63fd4cd0bfdd8c957d92d6b97f3ad0c2ab67539747dcb1642a93f5910ea84633c7675cbab3f09b61af2eda35129377c773129822e695d3048b7f7601955dca2560b1b699774c6f23959be241409da5515828524e95fd1551063b45f067fed2630348c1550e99ee116025586bf3ff50551917115fbd72cabe4087013a868c30abb5f1026f2d40173f869e87aabf82a5700e10022587095f1d77f013aa400a12db46d711c66477baa7a998a1a1c235f26a881740721eaa38b6e87eb223017520644a18a13d6f1797818accbc710b37ab96a7574d9c7816dfb44bf08221c860ac58f36971ddd1cdba2337f5f8dada15e7521b1d2d252cbd78f89a2e202ac52deeef8a75e5b92dad5e9ea3eff2263b3c1cc1",
            "5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e",
            "404142434445464748494a4b4c4d4e4f5051525354555658",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            (uint)0
        ];
        yield return
        [
            "f7605eb6f7ea9169ea6a9d224cdc78c6625c8c2febc6850c8d7d7403d812c4786099aeca711f242c9883f915019aed40103e1b7583b41b434f3945c06be0db220907d5114b9be3103225176eaaab115712580d44f46cd1a04cc90a73898677e4b5d41921231e5b3b839697babf90a26d00433f378b5a10133ef65b815c581ad65d840bd86427b3acbfdcf2a8de2dbe638358417453b732b6ad37ad6a097c6176191da83a6d5edb9384dfb1355c3ea898ec0435d4720a86b356f29961912aa857ed7b74d898cdba2337f5eddecb1cf8171653672429a83dfedb3f3c64c92ce6ffd97ae2bd21a507c989faf46f2832159915f53e92bbb264c79d941bb0824cb13387bde6df54bcc292938b3b0d93b57124174a047e9de05258ecc77f67bd27795bde8937e2d3119450484a1caae7c81267",
            "5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e",
            "404142434445464748494a4b4c4d4e4f5051525354555658",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            (uint)1
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [FXChaCha20.BlockSize + 1, FXChaCha20.BlockSize, FXChaCha20.NonceSize, FXChaCha20.KeySize, (uint)0];
        yield return [FXChaCha20.BlockSize - 1, FXChaCha20.BlockSize, FXChaCha20.NonceSize, FXChaCha20.KeySize, (uint)0];
        yield return [FXChaCha20.BlockSize, FXChaCha20.BlockSize, FXChaCha20.NonceSize + 1, FXChaCha20.KeySize, (uint)0];
        yield return [FXChaCha20.BlockSize, FXChaCha20.BlockSize, FXChaCha20.NonceSize - 1, FXChaCha20.KeySize, (uint)0];
        yield return [FXChaCha20.BlockSize, FXChaCha20.BlockSize, FXChaCha20.NonceSize, FXChaCha20.KeySize + 1, (uint)0];
        yield return [FXChaCha20.BlockSize, FXChaCha20.BlockSize, FXChaCha20.NonceSize, FXChaCha20.KeySize - 1, (uint)0];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, FXChaCha20.KeySize);
        Assert.AreEqual(24, FXChaCha20.NonceSize);
        Assert.AreEqual(64, FXChaCha20.BlockSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, uint counter)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);

        FXChaCha20.Encrypt(c, p, n, k, counter);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => FXChaCha20.Encrypt(c, p, n, k, counter));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, uint counter)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);

        FXChaCha20.Decrypt(p, c, n, k, counter);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => FXChaCha20.Decrypt(p, c, n, k, counter));
    }
}
