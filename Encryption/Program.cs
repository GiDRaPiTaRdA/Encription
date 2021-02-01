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

            //RsaAesStreamTest();

            //RsaAesBigDataStreamTest();

            Console.ReadKey();
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

        #region Rsa Aes 

        static void RsaAesBigDataStreamTest()
        {
            Stopwatch s = Stopwatch.StartNew();

            RsaAesEncription rsaAesEncription = new RsaAesEncription(LoadCert());

            string dataFile = @"data\test.txt";
            string extention = Path.GetExtension(dataFile);

            string encriptedFile = $@"data\encrypted{extention}";
            string decriptedFile = $@"data\decrypted{extention}";

            using (FileStream original = File.Open(dataFile, FileMode.Open))
            using (FileStream encrypted = File.Open(encriptedFile, FileMode.Create))
            {
                rsaAesEncription.EncryptStream(original, encrypted);
            }

            Console.WriteLine($"Encryption in {s.ElapsedMilliseconds}");
            s.Restart();

            using (FileStream encrypted = File.Open(encriptedFile, FileMode.Open))
            using (FileStream decripted = File.Open(decriptedFile, FileMode.Create))
            {
                rsaAesEncription.DecryptStream(encrypted, decripted);
            }

            Console.WriteLine($"Decryption in {s.ElapsedMilliseconds}");
        }


        static void RsaAesStreamTest()
        {
            Stopwatch s = Stopwatch.StartNew();

            RsaAesEncription rsaAesEncription = new RsaAesEncription(LoadCert());


            string data = "Hello world!";
            byte[] dataBytes = EncryptionProvider.StringToBytes(data);

            byte[] encryptedData = rsaAesEncription.EncryptTest(dataBytes);

            byte[] decryptedData = rsaAesEncription.DecryptTest(encryptedData);
        }

        #endregion

        static X509Certificate2 LoadCert()
        {
            X509Certificate2 cert = EncryptionProvider.LoadCertificate(StoreName.My, StoreLocation.CurrentUser, "EgyptAC")[0];
            return cert;
        }
    }
}
