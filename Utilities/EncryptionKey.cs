using System;

namespace Utilities
{
    public ref struct EncryptionKey
    {
        public EncryptionKey(ReadOnlySpan<byte> key, ReadOnlySpan<byte> salt)
        {
            Key = key;
            Salt = salt;
        }

        public ReadOnlySpan<byte> Salt { get; }

        public ReadOnlySpan<byte> Key { get; }
    }
}
