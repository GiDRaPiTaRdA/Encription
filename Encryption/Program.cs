using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EncryptionCore.Data;
using EncryptionCore;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using CustomConsole;
using Console = CustomConsole.Console;


namespace Encryption
{
    class Program
    {
        //D:\фотки\Lambo\post\post\VideoCapture_20201019-212807.jpg

        private static RsaAesEncription rsaAesEncription;

        private static string Source { get; set; } = @"data\vpn.rar";

        private static string encryptFile = @"data\encrypted.dat";
        private static string decryptFile = @"data\decrypted.rar";

        static void Main(string[] args)
        {
            rsaAesEncription = new RsaAesEncription(LoadCert("test"));

            Dictionary<string, Action> commands = new Dictionary<string, Action>()
            {
                {"set source", SetSource },
                {"encrypt", Encrypt },
                {"decrypt", Decrypt },
                {"e", Encrypt },
                {"d", Decrypt },
                {"t", Test }
            };

            ConsoleMenu.Help(commands);

            while (ConsoleMenu.Menu(commands));

            //LoadCertAndKeyType();

            //RsaTest();

            //RsaAesStreamTest();

            RsaAesBigDataStreamTest();

            Console.ReadKey();
        }

        private static void Test()
        {
            X509Certificate2 cert = EncryptionProvider.LoadCertificate(StoreName.My, StoreLocation.CurrentUser, "test")[0];

            //X509Certificate2 cert = new X509Certificate2(
            //    File.ReadAllBytes(@"C:\Users\Maxim\source\repos\VisualStudio\Encription\EncryptionCore\Cert\Certificates\test.pfx"),
            //    "1");

            using (RSA rsa = cert.GetRSAPublicKey())
            {
                CngKeyUsages s = ((RSACng)rsa).Key.KeyUsage;
            }
        }

        private static void SetSource()
        {
            do
            {
                string source = Console.ReadType<string>();

                if (source == "exit")
                {
                    return;
                }

                if (File.Exists(source))
                {
                    Source = source;
                    Console.WriteLine($"Source succesfuly set {source}",ConsoleColor.Green);
                    return;
                }
                else
                {
                    Console.WriteLine($"Source file {source} not found", ConsoleColor.Red);
                }


            }
            while (true);

        }

        private static void Encrypt()
        {
            Stopwatch s = Stopwatch.StartNew();

            using (FileStream original = File.Open(Source, FileMode.Open))
            using (FileStream encrypted = File.Open(encryptFile, FileMode.Create))
            {
                rsaAesEncription.EncryptStream(original, encrypted);
            }

            Console.WriteLine($"Encryption finished in {s.ElapsedMilliseconds}");
        }

        private static void Decrypt()
        {
            Stopwatch s = Stopwatch.StartNew();

            using (FileStream encrypted = File.Open(encryptFile, FileMode.Open))
            using (FileStream decripted = File.Open(decryptFile, FileMode.Create))
            {
                rsaAesEncription.DecryptStream(encrypted, decripted);
            }

            Console.WriteLine($"Decryption finished in {s.ElapsedMilliseconds}");
        }

        public static void RsaAesBigDataStreamTest()
        {
            Stopwatch s = Stopwatch.StartNew();

            RsaAesEncription rsaAesEncription = new RsaAesEncription(LoadCert("test"));

            string path = AppDomain.CurrentDomain.BaseDirectory;

            string dir = $@"{path}data";
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

            Console.WriteLine($"Decryption in {s.ElapsedMilliseconds}");
        }

        static X509Certificate2 LoadCert(string certName)
        {
            X509Certificate2 cert = EncryptionProvider.LoadCertificate(StoreName.My, StoreLocation.CurrentUser, certName)[0];
            return cert;
        }
    }
}
