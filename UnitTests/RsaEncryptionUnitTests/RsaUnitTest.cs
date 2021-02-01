
using EncryptionCore;
using NUnit.Framework;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using UnitTestTools;

namespace RsaEncryptionUnitTests
{
    [TestFixture]
    public class RsaUnitTest
    {
        public string original = "Hello world!";

        [Test]
        public void RsaTest()
        {
            RsaEncryptionProvider rsaEncryption = new RsaEncryptionProvider(LoadCert());

            byte[] originalBytes = EncryptionProvider.StringToBytes(original);

            byte[] encrypted = rsaEncryption.Encrypt(originalBytes);

            byte[] decrypted = rsaEncryption.Decrypt(encrypted);

            Assertions.CompareHash(originalBytes, decrypted);
        }

        [Test]
        public void RsaTextTest()
        {
            RsaEncryptionProvider rsaEncryption = new RsaEncryptionProvider(LoadCert());

            byte[] originalBytes = EncryptionProvider.StringToBytes(original);

            byte[] encrypted = rsaEncryption.EncryptText(original);

            string decrypted = rsaEncryption.DecryptText(encrypted);

            Assert.IsTrue(original == decrypted);
        }

        static X509Certificate2 LoadCert()
        {
            X509Certificate2 cert = EncryptionProvider.LoadCertificate(StoreName.My, StoreLocation.CurrentUser, "EgyptAC")[0];
            return cert;
        }
    }
}
