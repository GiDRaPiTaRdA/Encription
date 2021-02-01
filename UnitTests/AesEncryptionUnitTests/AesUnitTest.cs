
using EncryptionCore;
using NUnit.Framework;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using UnitTestTools;

namespace AesEncryptionUnitTests
{
    [TestFixture]
    public class AesUnitTest
    {
        public string original = "Hello world!";

        [Test]
        public void AesTest()
        {
            byte[] data = EncryptionProvider.StringToBytes(original);

            var key = AesEncryption.GenerateKey();

            byte[] encrypted = AesEncryption.EncryptTest(data, key);

            byte[] decrypted = AesEncryption.DecryptTest(encrypted, key);

            Assert.IsTrue(Enumerable.SequenceEqual(data, decrypted));
        }

        [Test]
        public void Aes()
        {
            byte[] data = EncryptionProvider.StringToBytes(original);

            var key = AesEncryption.GenerateKey();

            byte[] encrypted = AesEncryption.Encrypt(data, key);

            byte[] decrypted = AesEncryption.Decrypt(encrypted, key);

            Assert.IsTrue(Enumerable.SequenceEqual(data, decrypted));
        }

        [Test]
        public void AesTextTest()
        {
            var key = AesEncryption.GenerateKey();

            byte[] encrypted = AesEncryption.EncryptText(original, key);

            string decrypted = AesEncryption.DecryptText(encrypted, key);

            Assert.IsTrue(original == decrypted);
        }

        [Test]
        public void AesStreamTest()
        {
            byte[] dataIn = AesEncryption.StringToBytes(original);

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

            Assert.IsTrue(Enumerable.SequenceEqual(dataIn, decryptedBytes));
        }

        [Test]
        public void AesBigDataStreamTest()
        {
            Stopwatch s = Stopwatch.StartNew();

            byte[] key = AesEncryption.GenerateKey();

            string path = AppDomain.CurrentDomain.BaseDirectory;

            string dir = $@"{path}data\aes";
            string dataFile = $@"{dir}\Video.rar";
            string extention = Path.GetExtension(dataFile);

            string encriptedFile = $@"{dir}\encrypted{extention}";
            string decriptedFile = $@"{dir}\decrypted{extention}";

            // Encrypt
            using (FileStream original = File.Open(dataFile, FileMode.Open))
            using (FileStream encrypted = File.Open(encriptedFile, FileMode.Create))
            {
                AesEncryption.EncryptStream(original, encrypted, key);
            }

            Console.WriteLine($"Encryption in {s.ElapsedMilliseconds}");
            s.Restart();

            // Decrypt
            using (FileStream encrypted = File.Open(encriptedFile, FileMode.Open))
            using (FileStream decripted = File.Open(decriptedFile, FileMode.Create))
            {
                AesEncryption.DecryptStream(encrypted, decripted, key);
            }

            Console.WriteLine($"Decryption in {s.ElapsedMilliseconds}");


            // Check
            using (FileStream fileStream = File.Open(dataFile, FileMode.Open))
            {
                using (FileStream decripted = File.Open(decriptedFile, FileMode.Open))
                {
                    if (fileStream.Length != decripted.Length)
                    {
                        Assert.Fail($"Decripted and original streams have different length, original: {fileStream.Length} decrypted: {decripted.Length}");
                    }
                    else
                    {
                        Md5HashProvider hashProvider = new Md5HashProvider();

                        ulong originalHash =  hashProvider.Hash(fileStream);
                        ulong decryptedHash = hashProvider.Hash(decripted);

                        Assert.IsTrue(originalHash== decryptedHash, $"Hash does not match, original: {originalHash} decrypted: {decryptedHash}");
                    }
                }
            }

            //Assert.Pass();
        }
    }
}
