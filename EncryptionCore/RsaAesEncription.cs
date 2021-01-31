using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionCore
{
    public class RsaAesEncription
    {
        RsaEncryptionProvider RsaEncryptionProvider { get; }

        public RsaAesEncription(X509Certificate2 cert)
        {
            this.RsaEncryptionProvider = new RsaEncryptionProvider(cert);
        }

        public void EncryptStream(Stream dataStream, Stream encryptStream)
        {
            byte[] key = AesEncryption.GenerateKey();

            byte[] encryptedKey = this.RsaEncryptionProvider.Encrypt(key);

            encryptStream.Write(encryptedKey, 0, encryptedKey.Length);

            AesEncryption.EncryptStream(dataStream, encryptStream, key);
        }


        public void DecryptStream(Stream encryptedStream, Stream dataStream)
        {
            byte[] encryptedKey = new byte[512];
            encryptedStream.Read(encryptedKey, 0, encryptedKey.Length);

            byte[] key = this.RsaEncryptionProvider.Decrypt(encryptedKey);

            AesEncryption.DecryptStream(dataStream, encryptedStream, key);
        }
    }
}
