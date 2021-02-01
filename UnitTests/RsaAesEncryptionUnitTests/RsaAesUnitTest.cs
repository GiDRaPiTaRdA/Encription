
using EncryptionCore;
using NUnit.Framework;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using UnitTestTools;

namespace RsaAesEncryptionUnitTests
{
    [TestFixture]
    public class RsaAesUnitTest
    {
        public string original = "Hello world!";

        [Test]
        public void RsaAesBigDataStreamTest()
        {
            Stopwatch s = Stopwatch.StartNew();

            RsaAesEncription rsaAesEncription = new RsaAesEncription(LoadCert());

            string path = AppDomain.CurrentDomain.BaseDirectory;

            string dir = $@"{path}data\rsaaes";
            string dataFile = $@"{dir}\Video.rar";
            string extention = Path.GetExtension(dataFile);

            string encriptedFile = $@"{dir}\encrypted{extention}";
            string decriptedFile = $@"{dir}\decrypted{extention}";

            // Encrypt
            using (FileStream original = File.Open(dataFile, FileMode.Open))
            using (FileStream encrypted = File.Open(encriptedFile, FileMode.Create))
            {
                rsaAesEncription.EncryptStream(original, encrypted);
            }

            Console.WriteLine($"Encryption in {s.ElapsedMilliseconds}");
            s.Restart();

            // Decrypt
            using (FileStream encrypted = File.Open(encriptedFile, FileMode.Open))
            using (FileStream decripted = File.Open(decriptedFile, FileMode.Create))
            {
                rsaAesEncription.DecryptStream(encrypted, decripted);
            }

            // Check
            using (FileStream original = File.Open(dataFile, FileMode.Open))
            using (FileStream decripted = File.Open(decriptedFile, FileMode.Open))
            {
                if (original.Length != decripted.Length)
                {
                    Assert.Fail($"Decripted and original streams have different length, original: {original.Length} decrypted: {decripted.Length}");
                }
                else
                {
                    Assertions.CompareHash(original, decripted);
                }
            }

            Console.WriteLine($"Decryption in {s.ElapsedMilliseconds}");
        }

        [Test]
        public void RsaAesStreamTest()
        {
            RsaAesEncription rsaAesEncription = new RsaAesEncription(LoadCert());

            string data = "Hello world!";
            byte[] dataBytes = EncryptionProvider.StringToBytes(data);

            byte[] encryptedData = rsaAesEncription.EncryptTest(dataBytes);

            byte[] decryptedData = rsaAesEncription.DecryptTest(encryptedData);

            Assertions.CompareHash(dataBytes, decryptedData);
        }


        static X509Certificate2 LoadCert()
        {
            X509Certificate2 cert = EncryptionProvider.LoadCertificate(StoreName.My, StoreLocation.CurrentUser, "EgyptAC")[0];
            return cert;
        }
    }
}
