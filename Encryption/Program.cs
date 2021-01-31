using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EncryptionCore.Data;
using EncryptionCore;
using System.Diagnostics;

namespace Encryption
{
    class Program
    {
        static void Main(string[] args)
        {
            //LoadCertAndKeyType();

            //RsaTest();

            //AesTest();

            //AesStreamTest();

            //AesBigDataStreamTest();

            RsaAesBigDataStreamTest();

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

        static void AesStreamTest()
        {
            using (var random = new RNGCryptoServiceProvider())
            {
                var key = new byte[16];
                random.GetBytes(key);

                using (MemoryStream encrypted = new MemoryStream())
                {
                    byte[] dataIn = AesEncryption.StringToBytes("Hello world!");

                    using (MemoryStream original = new MemoryStream(dataIn))
                    {
                        using (MemoryStream decripted = new MemoryStream())
                        {
                            AesEncryption.EncryptStream(original, encrypted, key);

                            AesEncryption.DecryptStream(encrypted, decripted, key);

                            string decrypted = AesEncryption.BytesToString(decripted.ToArray());

                            //string decrypted = AesEncryption.DecryptText(encrypted.ToArray(), key);
                        }
                    }
                }
            }
        }


        static void AesBigDataStreamTest()
        {
            Stopwatch s = Stopwatch.StartNew();

            byte[] key;
            using (RNGCryptoServiceProvider random = new RNGCryptoServiceProvider())
            {
                key = new byte[16];
                random.GetBytes(key);
            }

            using (FileStream original = File.Open(@"data\data.rar", FileMode.Open))
            using (FileStream encrypted = File.Open(@"data\encripted.cript", FileMode.Create))
            {
                AesEncryption.EncryptStream(original, encrypted, key);
            }

            Console.WriteLine($"Encryption in {s.ElapsedMilliseconds}");
            s.Restart();

            using (FileStream encrypted = File.Open(@"data\encripted.cript", FileMode.Open))
            using (FileStream decripted = File.Open(@"data\decripted.rar", FileMode.Create))
            {
                AesEncryption.DecryptStream(encrypted, decripted, key);
            }

            Console.WriteLine($"Decryption in {s.ElapsedMilliseconds}");

        }

        static void RsaAesBigDataStreamTest()
        {
            RsaAesEncription rsaAesEncription = new RsaAesEncription(LoadCert());

            using (FileStream original = File.Open(@"data\data.rar", FileMode.Open))
            using (FileStream encrypted = File.Open(@"data\encripted.cript", FileMode.Create))
            {
                rsaAesEncription.EncryptStream(original,encrypted);
            }

            using (FileStream encrypted = File.Open(@"data\encripted.cript", FileMode.Open))
            using (FileStream decripted = File.Open(@"data\decripted.rar", FileMode.Create))
            {
                rsaAesEncription.DecryptStream(encrypted, decripted);
            }
        }


        static void LoadCertAndKeyType()
        {
            KeyType keyType = EncryptionProvider.GetCertificateType(LoadCert());
        }

        static X509Certificate2 LoadCert()
        {
            X509Certificate2 cert = EncryptionProvider.LoadCertificate(StoreName.My, StoreLocation.CurrentUser, "EgyptAC")[0];
            return cert;
        }
    }
}
