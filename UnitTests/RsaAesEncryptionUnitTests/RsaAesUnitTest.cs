
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
        private readonly TestDataProvider data = new TestDataProvider();

        [Test]
        [TestCase("test", "1111")]
        public void RsaAesBigDataStreamTest(string certName, string password)
        {
            // Data
            X509Certificate2 cert = this.data.GetTestCertificate(certName, password);


            Directory.CreateDirectory(this.data.DataRoot);

            Stopwatch s = Stopwatch.StartNew();

            RsaAesEncription rsaAesEncription = new RsaAesEncription(cert);

        
            // Encrypt
            using (FileStream original = File.Open(this.data.DataFile, FileMode.Open))
            using (FileStream encrypted = File.Open(this.data.EncryptedFile, FileMode.Create))
            {
                rsaAesEncription.EncryptStream(original, encrypted);
            }

            Console.WriteLine($"Encryption in {s.ElapsedMilliseconds}");
            s.Restart();

            // Decrypt
            using (FileStream encrypted = File.Open(this.data.EncryptedFile, FileMode.Open))
            using (FileStream decripted = File.Open(this.data.DecryptedFile, FileMode.Create))
            {
                rsaAesEncription.DecryptStream(encrypted, decripted);
            }

            // Check
            using (FileStream original = File.Open(this.data.DataFile, FileMode.Open))
            using (FileStream decripted = File.Open(this.data.DecryptedFile, FileMode.Open))
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
        [TestCase("test", "1111")]
        public void RsaAesStreamTest(string certName, string password)
        {
            // Data
            X509Certificate2 cert = this.data.GetTestCertificate(certName, password);


            RsaAesEncription rsaAesEncription = new RsaAesEncription(cert);

            byte[] dataBytes = EncryptionProvider.StringToBytes(this.data.DataFile);

            byte[] encryptedData = rsaAesEncription.EncryptTest(dataBytes);

            byte[] decryptedData = rsaAesEncription.DecryptTest(encryptedData);

            Assertions.CompareHash(dataBytes, decryptedData);
        }
    }
}
