using Geralt;

namespace FXChaCha20DotNet;

public static class FXChaCha20Poly1305
{
    public const int KeySize = XChaCha20Poly1305.KeySize;
    public const int NonceSize = XChaCha20Poly1305.NonceSize;
    public const int TagSize = XChaCha20Poly1305.TagSize;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkey = stackalloc byte[KeySize]; subkey.Clear();
        ChaCha20.Encrypt(subkey, subkey, nonce[..12], key);

        ChaCha20Poly1305.Encrypt(ciphertext, plaintext, nonce[12..], subkey, associatedData);
        SecureMemory.ZeroMemory(subkey);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkey = stackalloc byte[KeySize]; subkey.Clear();
        ChaCha20.Encrypt(subkey, subkey, nonce[..12], key);

        try {
            ChaCha20Poly1305.Decrypt(plaintext, ciphertext, nonce[12..], subkey, associatedData);
        }
        finally {
            SecureMemory.ZeroMemory(subkey);
        }
    }
}
