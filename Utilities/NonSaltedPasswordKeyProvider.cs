using System;

namespace Utilities
{
    public class NonSaltedPasswordKeyProvider : IPasswordKeyProvider
    {
        public NonSaltedPasswordKeyProvider(IPasswordKeyProvider keyProvider)
        {
            Decorated = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));
        }

        private IPasswordKeyProvider Decorated { get; }

        public int SaltBitSize => 0;

        public int KeyBitSize => Decorated.KeyBitSize;

        public int PasswordDeriviationIterations => Decorated.PasswordDeriviationIterations;

        public EncryptionKey GenerateKey()
        {
            var salt = new byte[SaltBitSize / 8];

            return GenerateKey(salt);
        }

        public EncryptionKey GenerateKey(ReadOnlySpan<byte> salt)
        {
            return Decorated.GenerateKey(salt);
        }
    }
}
