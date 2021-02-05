using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace RsaEncryptionUnitTests
{
    public class TestDataProvider
    {
        private const string testData = "TestData";

        public string TextData => "Hello world!";

        public X509Certificate2 GetTestCertificate(string certName, string password)
        {
            X509Certificate2 cert = new X509Certificate2(
                File.ReadAllBytes($@"{testData}\{certName}.pfx"),
                password);

            return cert;
        }
    }
}