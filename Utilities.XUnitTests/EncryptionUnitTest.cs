using Microsoft.Extensions.Options;
using System;
using System.Diagnostics.CodeAnalysis;
using Utilities;
using Xunit;

namespace XUnitTests
{
    [ExcludeFromCodeCoverage]

    public class EncryptionUnitTest
    {
        private const string Secret = "$3crE1";
        private const string PlainText = "The quick brown fox jumps over the head of the lazy dog.";
        private const string CipherText = "DAAAAAAAAAAAAAAAAAAAABAAAADZHGE2g+U0cCkaiXh7H/6sDxe5Dseq7w/WM+cVoWGJmOIDgC4PBbI2xIjbj/YYJl5GL1yJZRm2f6dxVKmGiRIDxJkhb69hGwQ=";

        private readonly IPasswordKeyProvider PasswordKeyProvider = new PasswordKeyProvider(() => Secret);
        private readonly IPasswordKeyProvider NonSaltedPasswordKeyProvider = new NonSaltedPasswordKeyProvider(new PasswordKeyProvider(() => Secret));
        private readonly IOptions<AesGcmEncryptionServiceOptions> NonceDisabledOptions = Options.Create(new AesGcmEncryptionServiceOptions { UseNonce = false });

        [Fact]
        public void TestPasswordKeyProvider()
        {
            var baseline = PasswordKeyProvider.GenerateKey();
            var testcase = PasswordKeyProvider.GenerateKey();

            Assert.Equal(32, testcase.Key.Length);
            Assert.Equal(16, testcase.Salt.Length);

            Assert.Equal(PasswordKeyProvider.KeyBitSize / 8, testcase.Key.Length);
            Assert.Equal(PasswordKeyProvider.SaltBitSize / 8, testcase.Salt.Length);

            Assert.NotEqual(Convert.ToBase64String(baseline.Key), Convert.ToBase64String(testcase.Key));
        }

        [Fact]
        public void TestNonSaltedPasswordKeyProvider()
        {
            var baseline = NonSaltedPasswordKeyProvider.GenerateKey();
            var testcase = NonSaltedPasswordKeyProvider.GenerateKey();
            
            Assert.Equal(32, testcase.Key.Length);
            Assert.Equal(0, testcase.Salt.Length);

            Assert.Equal(NonSaltedPasswordKeyProvider.KeyBitSize / 8, testcase.Key.Length);
            Assert.Equal(NonSaltedPasswordKeyProvider.SaltBitSize / 8, testcase.Salt.Length);

            Assert.Equal(Convert.ToBase64String(baseline.Key), Convert.ToBase64String(testcase.Key));
        }

        [Fact]
        public void TestSecurePasswordBasedEncryption()
        {
            var encryption = new AesGcmEncryptionService(PasswordKeyProvider, Options.Create(new AesGcmEncryptionServiceOptions()));

            var encrypted = encryption.Encrypt(PlainText);
            var decrypted = encryption.Decrypt(encrypted);

            Assert.Equal(PlainText, decrypted);
        }

        [Fact]
        public void TestRepeatablePasswordBasedEncryption()
        {
            var encryption = new AesGcmEncryptionService(NonSaltedPasswordKeyProvider, NonceDisabledOptions);

            var baseline = encryption.Encrypt(PlainText);
            var testcase = encryption.Encrypt(PlainText);

            var decrypted = encryption.Decrypt(testcase);

            Assert.Equal(baseline, testcase);
            Assert.Equal(CipherText, testcase);
            Assert.Equal(PlainText, decrypted);
        }
    }
}
