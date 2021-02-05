using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace AesEncryptionUnitTests
{
    public class TestDataProvider
    {
        private const string dir = "data";

        private const string testData = "TestData";

        private string Extention => Path.GetExtension(this.DataFile);

        private string Root => AppDomain.CurrentDomain.BaseDirectory;

        public string DataRoot => $@"{this.Root}\{dir}";

        public string TextData => "Hello world!";

        public string DataFile=> $@"{this.Root}\{testData}\data.rar";

        public string EncryptedFile => $@"{this.DataRoot}\encrypted{this.Extention}";
        public string DecryptedFile => $@"{this.DataRoot}\decrypted{this.Extention}";
    }
}