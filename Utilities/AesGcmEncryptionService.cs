using Microsoft.Extensions.Options;
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Utilities
{
    public class AesGcmEncryptionService : IEncryptionService
    {
        public AesGcmEncryptionService(IPasswordKeyProvider keyProvider, IOptions<AesGcmEncryptionServiceOptions> options)
        {
            KeyProvider = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));
            Options = options.Value;
        }

        private IPasswordKeyProvider KeyProvider { get; }

        private AesGcmEncryptionServiceOptions Options { get; }

        public string Encrypt(string plainText)
        {
            if (plainText == null)
                throw new ArgumentNullException(nameof(plainText));

            // Generate an encryption key
            var encryptionKey = KeyProvider.GenerateKey();

            // Get bytes of plain text string
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            // Get parameter sizes
            int nonceSize = AesGcm.NonceByteSizes.MaxSize;
            int tagSize = AesGcm.TagByteSizes.MaxSize;
            int cipherSize = plainBytes.Length;

            // We write everything into one big array for easier encoding
            int encryptedDataLength = 4 + nonceSize + 4 + tagSize + cipherSize;
            Span<byte> encryptedData = encryptedDataLength < 1024 ? stackalloc byte[encryptedDataLength] : new byte[encryptedDataLength].AsSpan();

            // Copy parameters
            BinaryPrimitives.WriteInt32LittleEndian(encryptedData.Slice(0, 4), nonceSize);
            BinaryPrimitives.WriteInt32LittleEndian(encryptedData.Slice(4 + nonceSize, 4), tagSize);
            var nonce = encryptedData.Slice(4, nonceSize);
            var tag = encryptedData.Slice(4 + nonceSize + 4, tagSize);
            var cipherBytes = encryptedData.Slice(4 + nonceSize + 4 + tagSize, cipherSize);

            // Generate secure nonce
            if (Options.UseNonce)
                RandomNumberGenerator.Fill(nonce);

            // Encrypt
            using var aes = new AesGcm(encryptionKey.Key);
            aes.Encrypt(nonce, plainBytes.AsSpan(), cipherBytes, tag);

            // Append salt
            var final = new byte[encryptionKey.Salt.Length + encryptedData.Length];
            encryptionKey.Salt.CopyTo(final);
            encryptedData.CopyTo(final.AsSpan(encryptionKey.Salt.Length));

            // Encode for transmission
            return Convert.ToBase64String(final);
        }

        public string Decrypt(string cipherText)
        {
            if (cipherText == null)
                throw new ArgumentNullException(nameof(cipherText));

            // Decode
            Span<byte> saltedEncryptedData = Convert.FromBase64String(cipherText).AsSpan();

            // Extract salt
            Span<byte> salt = saltedEncryptedData.Slice(0, KeyProvider.SaltBitSize / 8);

            var encryptionKey = KeyProvider.GenerateKey(salt);

            Span<byte> encryptedData = saltedEncryptedData[(KeyProvider.SaltBitSize / 8)..];

            var length = encryptedData.Length;
            // Extract parameter sizes
            int nonceSize = length >= 4 ? BinaryPrimitives.ReadInt32LittleEndian(encryptedData.Slice(0, 4)) : 0;
            int tagSize = length >= 4 + nonceSize + 4 ? BinaryPrimitives.ReadInt32LittleEndian(encryptedData.Slice(4 + nonceSize, 4)) : 0;
            int cipherSize = encryptedData.Length - 4 - nonceSize - 4 - tagSize;

            if (cipherSize < 0) cipherSize = 0;

            // Extract parameters
            var nonce = length >= 4 ? encryptedData.Slice(4, nonceSize) : new byte[AesGcm.NonceByteSizes.MaxSize];
            var tag = length >= 4 + nonceSize + 4 ? encryptedData.Slice(4 + nonceSize + 4, tagSize) : new byte[AesGcm.TagByteSizes.MaxSize];
            var cipherBytes = length >= 4 + nonceSize + 4 + tagSize ? encryptedData.Slice(4 + nonceSize + 4 + tagSize, cipherSize) : new byte[cipherSize];

            Span<byte> plainBytes = cipherSize < 1024 ? stackalloc byte[cipherSize] : new byte[cipherSize];

            // Decrypt
            using var aes = new AesGcm(encryptionKey.Key);

            try
            {
                aes.Decrypt(nonce, cipherBytes, tag, plainBytes);
            }
            catch (CryptographicException e)
            {
                throw new ArgumentException("Invalid Cipher", nameof(cipherText), e);
            }

            // Convert plain bytes back into string
            return Encoding.UTF8.GetString(plainBytes);
        }
    }
}
