using System;
using System.Security.Cryptography;
using System.Text;

namespace Utilities
{
    public class PasswordKeyProvider : IPasswordKeyProvider
    {
        public PasswordKeyProvider(Func<string> secretProvider)
        {
            SecretProvider = secretProvider ?? throw new ArgumentNullException(nameof(secretProvider));
        }

        private Func<string> SecretProvider { get; }

        public int SaltBitSize => 128;

        public int KeyBitSize => 256;

        public int PasswordDeriviationIterations => 1000;

        public EncryptionKey GenerateKey()
        {
            var salt = new byte[SaltBitSize / 8];
            using var randomProvider = new RNGCryptoServiceProvider();
            randomProvider.GetBytes(salt);

            return GenerateKey(salt);
        }

        public EncryptionKey GenerateKey(ReadOnlySpan<byte> salt)
        {
            const int MinSaltLength = 8;

            var saltBytes = salt.Length < MinSaltLength ? new byte[MinSaltLength] : salt.ToArray();

            var providedSecret = SecretProvider() ?? string.Empty;
            var secret = Encoding.UTF8.GetBytes(providedSecret);

#pragma warning disable S2053 // Hashes should include an unpredictable salt
            using var keyDeriviation = new Rfc2898DeriveBytes(secret, salt: saltBytes, iterations: PasswordDeriviationIterations);
#pragma warning restore S2053 // Hashes should include an unpredictable salt
            var key = keyDeriviation.GetBytes(KeyBitSize / 8);

            return new EncryptionKey(key, salt);
        }
    }
}
