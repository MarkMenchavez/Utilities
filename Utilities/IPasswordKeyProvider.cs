using System;

namespace Utilities
{
    public interface IPasswordKeyProvider
    {
        int SaltBitSize { get; }

        int KeyBitSize { get; }

        int PasswordDeriviationIterations { get; }

        EncryptionKey GenerateKey();

        EncryptionKey GenerateKey(ReadOnlySpan<byte> salt);
    }
}
