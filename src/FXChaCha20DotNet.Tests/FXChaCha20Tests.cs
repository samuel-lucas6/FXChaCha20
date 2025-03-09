namespace FXChaCha20DotNet.Tests;

[TestClass]
public class FXChaCha20Tests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "6fe3666cd55790f70af70ff893b45a9d1389af71b4b0b60154583d5285b842e5ede133d80e0dea4f0ce285470df72e257afa4b1944e4f9258777bc8cfd7dd1404df2e1db1841794dedb79fecea9832c85fe23cba6e3375c4525962b1b2536a2269e30b7a54e289ce1a345f893e399c02677a1470e2bcd0f867625c282fb66ed9543843ec3446018797d46a0fa277ad7aaaeb0fb411e0d0397b6665ca6d58d34bec26f4d207dfdf92cf7294acd0a5cf4c6584b159db2930d8a6c42249d70197b63cbefecae6d6b7f75b3c69d147148b2f580974080674a6c0284a07bc56c0c8ce6691294f9dfe054d3c9ee2a9019174145ccee0513bd217e7c9a6c20e23d1b0710269d32fbf14a0beb938d5fe76ba475418117827fafb5be43b33b390e7d256548376c2cc98ba3579f0355a580a6416f0",
            "5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e",
            "404142434445464748494a4b4c4d4e4f5051525354555657",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            (uint)0
        ];
        yield return
        [
            "7df5e3d75c5b7345a8f3d8fbb4d73dc94eac28b7636023cc545b60b3ff1c647f69cb132952b1c2c1172c44dd7f3ed4132f6c5d4bf4f5deea2e605c1823a867985e7757a871440c86c5d4250afb23ec78a1a413af58fecb2777286e8362529404ec03ef9c09819396ca7a84bcd0b7c8516bd78c4bd77a7fd6efc26a62cb539fbb27ede4d4e686befc4d783ad85b0cc7265346750e4b69acc06d0318f55ec989dc359420489fb7495f328defed5698771a179d981931ce4ee0d4a4d94e7a9bb47e1c7bd62af614a0beb938c0fa67b35811155f3226ffee1ee27a22afdeebd35e44d079c5c894b26c2eda205c11196a1fa806b2d1e32711002bbb4d4e251277a36756b31564568a495f1a09d58324fa067b2adb470f3b5f9840c876ea4c42043c8049d4604d59ae280d0507e5e009edfdb7",
            "5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e",
            "404142434445464748494a4b4c4d4e4f5051525354555657",
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
