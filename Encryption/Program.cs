using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EncryptionCore.Data;
using EncryptionCore;

namespace Encryption
{
    class Program
    {
        static void Main(string[] args)
        {
            //LoadCertAndKeyType();

            //RsaTest();

            //AesTest();

            RsaStreamTest();

            Console.ReadKey();
        }

        static void AesTest()
        {
            string original = "Hello world!";

            using (var random = new RNGCryptoServiceProvider())
            {
                var key = new byte[16];
                random.GetBytes(key);

                byte[] encrypted = AesEncryption.EncryptText(original, key);

                string decrypted = AesEncryption.DecryptText(encrypted, key);

                //Display the original data and the decrypted data.
                Console.WriteLine("Original:   {0}", original);
                Console.WriteLine("Key:   {0}", Convert.ToBase64String(key));
                Console.WriteLine("Encrypted (b64-encode): {0}", Convert.ToBase64String(encrypted));
                Console.WriteLine("Round Trip: {0}", decrypted);

            }
        }

        static void RsaTest()
        {
            EncryptionProvider encription = new RsaEncryptionProvider(EncryptionProvider.LoadCertificate(StoreName.My, StoreLocation.CurrentUser, "test")[0]);

            byte[] data = encription.EncryptText("Hello world!");

            Console.WriteLine(BitConverter.ToString(data));

            string text = encription.DecryptText(data);

            Console.WriteLine(text);
            Console.ReadLine();
        }

        static void RsaStreamTest()
        {

            using (var random = new RNGCryptoServiceProvider())
            {
                var key = new byte[16];
                random.GetBytes(key);

                using (Stream encrypted = new MemoryStream())
                {
                    using (MemoryStream original = new MemoryStream(AesEncryption.StringToBytes("Hello world!")))
                    {
                        AesEncryption.Encrypt1(original, encrypted, key);

                        string decrypted = AesEncryption.DecryptText(((MemoryStream)encrypted).ToArray(), key);


                        // X509KeyStorageFlags

                    }
                }


            }
        }

        static void LoadCertAndKeyType()
        {
            X509Certificate2 cert = EncryptionProvider.LoadCertificate(StoreName.My, StoreLocation.CurrentUser, "test")[0];
            KeyType keyType = EncryptionProvider.GetCertificateType(cert);
        }
    }
}
