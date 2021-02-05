using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
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
            this.RsaEncryptionProvider = new RsaEncryptionProvider(cert,RSAEncryptionPadding.OaepSHA512);
        }

        public byte[] EncryptText(string data) =>
            this.Encrypt(EncryptionProvider.StringToBytes(data));

        public string DecryptText(byte[] encryptedData) =>
            EncryptionProvider.BytesToString(this.Decrypt(encryptedData));

        public byte[] Encrypt(byte[] data)
        {
            using (MemoryStream dataStream = new MemoryStream(data))
            {
                using (MemoryStream encryptedStream = new MemoryStream())
                {
                    this.EncryptStream(dataStream, encryptedStream);

                    return encryptedStream.ToArray();
                }
            }
        }


        public byte[] EncryptTest(byte[] data)
        {
            byte[] key = AesEncryption.GenerateKey();

            byte[] encryptedKey = this.RsaEncryptionProvider.Encrypt(key);

            byte[] aesEncrypted = AesEncryption.EncryptTest(data, key);

            byte[] rsaAesEncrypted = this.ConcatArrays(encryptedKey,aesEncrypted);

            return rsaAesEncrypted;
        }

        public byte[] DecryptTest(byte[] encryptedData)
        {
            byte[] encryptedKey = encryptedData.Take(512).ToArray();

            byte[] key = this.RsaEncryptionProvider.Decrypt(encryptedKey);

            byte[] aesEncrypted = encryptedData.Skip(encryptedKey.Length).ToArray();

            byte[] data = AesEncryption.Decrypt(aesEncrypted, key);

            return data;
        }

        private byte[] ConcatArrays(byte[] bytes1, byte[] bytes2)
        {
            byte[] z = new byte[bytes1.Length + bytes2.Length];
            bytes1.CopyTo(z, 0);
            bytes2.CopyTo(z, bytes1.Length);

            return z;
        }

        public byte[] Decrypt(byte[] encryptedData)
        {
            using (MemoryStream encryptedStream = new MemoryStream(encryptedData))
            {
                using (MemoryStream dataStream = new MemoryStream())
                {
                    this.DecryptStream(encryptedStream, dataStream);

                    return dataStream.ToArray();
                }
            }
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
            byte[] encryptedKey = new byte[512];    // rsa encripted
            encryptedStream.Read(encryptedKey, 0, encryptedKey.Length);

            byte[] key = this.RsaEncryptionProvider.Decrypt(encryptedKey);

            AesEncryption.DecryptStream(encryptedStream, dataStream, key);
        }
    }
}
