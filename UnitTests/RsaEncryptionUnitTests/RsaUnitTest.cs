
using EncryptionCore;
using NUnit.Framework;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EncryptionCore.Data;
using UnitTestTools;

namespace RsaEncryptionUnitTests
{
    [TestFixture]
    public class RsaUnitTest
    {
        private readonly TestDataProvider data = new TestDataProvider();

        [Test]
        [TestCase("test", "1111")]
        public void RsaTest(string certName, string password)
        {
            // Data
            X509Certificate2 cert = this.data.GetTestCertificate(certName, password);

            byte[] originalBytes = EncryptionProvider.StringToBytes(this.data.TextData);


            RsaEncryptionProvider rsaEncryption = new RsaEncryptionProvider(cert, RSAEncryptionPadding.OaepSHA512);

            byte[] encrypted = rsaEncryption.Encrypt(originalBytes);

            byte[] decrypted = rsaEncryption.Decrypt(encrypted);

            Assertions.CompareHash(originalBytes, decrypted);
        }

        [Test]
        [TestCase("test", "1111")]
        public void RsaTextTest(string certName, string password)
        {
            // Data
            X509Certificate2 cert = this.data.GetTestCertificate(certName, password);


            RsaEncryptionProvider rsaEncryption = new RsaEncryptionProvider(cert, RSAEncryptionPadding.OaepSHA512);

            byte[] encrypted = rsaEncryption.EncryptText(this.data.TextData);

            string decrypted = rsaEncryption.DecryptText(encrypted);

            Assert.IsTrue(this.data.TextData == decrypted);
        }
    }
}
