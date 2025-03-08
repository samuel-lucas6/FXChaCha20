using Geralt;

namespace FXChaCha20DotNet;

public static class FXChaCha20
{
    public const int KeySize = XChaCha20.KeySize;
    public const int NonceSize = XChaCha20.NonceSize;
    public const int BlockSize = XChaCha20.BlockSize;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, uint counter = 0)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkey = stackalloc byte[KeySize]; subkey.Clear();
        ChaCha20.Encrypt(subkey, subkey, nonce[..12], key);

        ChaCha20.Encrypt(ciphertext, plaintext, nonce[12..], subkey, counter);
        SecureMemory.ZeroMemory(subkey);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, uint counter = 0)
    {
        Encrypt(plaintext, ciphertext, nonce, key, counter);
    }
}
