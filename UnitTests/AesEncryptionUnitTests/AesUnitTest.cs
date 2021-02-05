using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using EncryptionCore;
using NUnit.Framework;
using UnitTestTools;

namespace AesEncryptionUnitTests
{
    [TestFixture]
    public class AesUnitTest
    {
        private readonly TestDataProvider data = new TestDataProvider();

        [Test]
        public void AesTest()
        {
            byte[] textData = EncryptionProvider.StringToBytes(this.data.TextData);

            byte[] key = AesEncryption.GenerateKey();

            byte[] encrypted = AesEncryption.EncryptTest(textData, key);

            byte[] decrypted = AesEncryption.DecryptTest(encrypted, key);

            Assert.IsTrue(textData.SequenceEqual(decrypted));
        }

        [Test]
        public void Aes()
        {
            byte[] data = EncryptionProvider.StringToBytes(this.data.TextData);

            byte[] key = AesEncryption.GenerateKey();

            byte[] encrypted = AesEncryption.Encrypt(data, key);

            byte[] decrypted = AesEncryption.Decrypt(encrypted, key);

            Assert.IsTrue(data.SequenceEqual(decrypted));
        }

        [Test]
        public void AesTextTest()
        {
            byte[] key = AesEncryption.GenerateKey();

            byte[] encrypted = AesEncryption.EncryptText(this.data.TextData, key);

            string decrypted = AesEncryption.DecryptText(encrypted, key);

            Assert.IsTrue(this.data.TextData == decrypted);
        }

        [Test]
        public void AesStreamTest()
        {
            // Data
            Directory.CreateDirectory(this.data.DataRoot);

            byte[] dataIn = AesEncryption.StringToBytes(this.data.TextData);

            byte[] key = AesEncryption.GenerateKey();



            byte[] encryptedBytes;

            byte[] decryptedBytes;

            using (MemoryStream encrypted = new MemoryStream())
            {
                using (MemoryStream original = new MemoryStream(dataIn))
                {
                    AesEncryption.EncryptStream(original, encrypted, key);
                }

                encryptedBytes = encrypted.ToArray();
            }

            using (MemoryStream encrypted = new MemoryStream(encryptedBytes))
            {
                using (MemoryStream decripted = new MemoryStream())
                {
                    AesEncryption.DecryptStream(encrypted, decripted, key);

                    decryptedBytes = decripted.ToArray();
                }
            }

            Assert.IsTrue(dataIn.SequenceEqual(decryptedBytes));
        }

        [Test]
        public void AesBigDataStreamTest()
        {
            Directory.CreateDirectory(this.data.DataRoot);


            Stopwatch s = Stopwatch.StartNew();

            byte[] key = AesEncryption.GenerateKey();

            // Encrypt
            using (FileStream original = File.Open(this.data.DataFile, FileMode.Open))
            using (FileStream encrypted = File.Open(this.data.EncryptedFile, FileMode.Create))
            {
                AesEncryption.EncryptStream(original, encrypted, key);
            }

            Console.WriteLine($"Encryption in {s.ElapsedMilliseconds}");
            s.Restart();

            // Decrypt
            using (FileStream encrypted = File.Open(this.data.EncryptedFile, FileMode.Open))
            using (FileStream decripted = File.Open(this.data.DecryptedFile, FileMode.Create))
            {
                AesEncryption.DecryptStream(encrypted, decripted, key);
            }

            Console.WriteLine($"Decryption in {s.ElapsedMilliseconds}");


            // Check
            using (FileStream fileStream = File.Open(this.data.DataFile, FileMode.Open))
            {
                using (FileStream decripted = File.Open(this.data.DecryptedFile, FileMode.Open))
                {
                    if (fileStream.Length != decripted.Length)
                    {
                        Assert.Fail($"Decripted and original streams have different length, original: {fileStream.Length} decrypted: {decripted.Length}");
                    }
                    else
                    {
                        Assertions.CompareHash(fileStream, decripted);
                    }
                }
            }

            //Assert.Pass();
        }
    }
}
