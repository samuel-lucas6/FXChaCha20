using Geralt;

namespace FXChaCha20DotNet;

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha
public static class ExtendedChaCha20
{
    public const int KeySize = XChaCha20.KeySize;
    public const int NonceSize = XChaCha20.NonceSize;
    public const int BlockSize = XChaCha20.BlockSize;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, uint counter = 0)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkey = stackalloc byte[HChaCha20.OutputSize];
        HChaCha20.DeriveKey(subkey, key, nonce[..HChaCha20.NonceSize]);

        Span<byte> subnonce = stackalloc byte[ChaCha20.NonceSize]; subnonce.Clear();
        nonce[HChaCha20.NonceSize..].CopyTo(subnonce[4..]);

        ChaCha20.Encrypt(ciphertext, plaintext, subnonce, subkey, counter);
        SecureMemory.ZeroMemory(subkey);
        SecureMemory.ZeroMemory(subnonce);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, uint counter = 0)
    {
        Encrypt(plaintext, ciphertext, nonce, key, counter);
    }
}
