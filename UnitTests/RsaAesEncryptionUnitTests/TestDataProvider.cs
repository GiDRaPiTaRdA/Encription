using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace RsaAesEncryptionUnitTests
{
    public class TestDataProvider
    {
        private const string dir = "data";

        private const string testData = "TestData";

        private string Extention => Path.GetExtension(this.DataFile);

        private string Root => AppDomain.CurrentDomain.BaseDirectory;

        public string DataRoot => $@"{this.Root}\{dir}";

        public string TextData => "Hello world!";

        public string DataFile => $@"{this.Root}\{testData}\data.rar";

        public string EncryptedFile => $@"{this.DataRoot}\encrypted{this.Extention}";
        public string DecryptedFile => $@"{this.DataRoot}\decrypted{this.Extention}";

        public X509Certificate2 GetTestCertificate(string certName, string password)
        {
            X509Certificate2 cert = new X509Certificate2(
                File.ReadAllBytes($@"{testData}\{certName}.pfx"),
                password);

            return cert;
        }
    }
}