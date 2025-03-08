namespace FXChaCha20DotNet.Tests;

[TestClass]
public class FXXChaCha20Tests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "d87e03647f09327bb5749167b1a63e9facaf6d540d82fa5a9d4c7c24597dfd98532a0f592c5af148d90a2a57e53bd020630faf8216bcab914049cd2e6ab0e36e61d0b60e286b4166b5f9b4e7aedbe867b5c29156ad278d04f71695d9512d24428e17d742da2cd468e7eeeead5d06dc5c4b0311412a191326d0adb518ed6e0ccd2428c2629a4209b14c0dfe52adbef103b5b1a4409a9d32c04f77e1529a0ac658d597b3ef929a18bf0567c51c590e4a6fae9c4aef4d27a54c7e7893ded546c19c50d49d438c2ef8d071a6710cb8d62266547b52f4752659f1fc6522ad39de90a0c7926ef61e54a4cd00c5bf9296b86b26e9d0f440922ea2e00d75ce1d043d6cdf6dac44198d5a617aa348b1881cf6a7aa485edc30eeda03c0324ffad2b24318de5a291f7a26953cca2fbcc47d7efca425",
            "5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e",
            "404142434445464748494a4b4c4d4e4f505152535455565860626466",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            (uint)0
        ];
        yield return
        [
            "51d7b4026c714b6ef0bdf3f0f094e766a48c855ba074db0cf11497db1c622a1f8e3fcf11dc7f9f67eaf6f5f91c01944d0315587a3c501d3499afb528e170058c2e67d626df4004b01e0db157f4eab001befeb85bd38329de4339ea1b95008117d5b2a8a19cc454bb006fd50c591c4d72a0cf77fd4174ea42377edbf5c914c9914b87875d8c7ef1db67e22205a4ce6e6f5f3453f2383b53f1b92c3de431d7d1b2949767f11c1de8df0ed6b2d6c1b16828a2838c089832fbe71077d55d5d7768d073be411cc45a617aa348a48c0dffb8ef45109631ebcf46c6735ee69cbe4210ce0926187e2a9d659d05a9c2346df2ad7dce8f11ce91f386063c664c6fe99d3052d826c08a73529406c017cea80d5809a78be913c3ccc10e188a192fccd8412ae96e0f2c42f4713b2b42c15a925ff6100c",
            "5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e",
            "404142434445464748494a4b4c4d4e4f505152535455565860626466",
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
