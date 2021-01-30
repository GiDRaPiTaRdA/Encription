using EncriptionCore;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using EncriptionCore.Data;


namespace Encription
{
    class Program
    {
        static void Main(string[] args)
        {

            //LoadCertAndKeyType();

            //RsaTest();

            //AesTest();

            RsaStreamTest();

            Console.ReadKey();
        }

        static void AesTest()
        {
            string original = "Hello world!";

            using (var random = new RNGCryptoServiceProvider())
            {
                var key = new byte[16];
                random.GetBytes(key);

                byte[] encrypted = AesEncription.EncryptText(original, key);

                string decrypted = AesEncription.DecryptText(encrypted, key);

                //Display the original data and the decrypted data.
                Console.WriteLine("Original:   {0}", original);
                Console.WriteLine("Key:   {0}", Convert.ToBase64String(key));
                Console.WriteLine("Encrypted (b64-encode): {0}", Convert.ToBase64String(encrypted));
                Console.WriteLine("Round Trip: {0}", decrypted);

            }
        }

        static void RsaTest()
        {
            EncriptionProvider encription = new RsaEncriptionProvider(EncriptionProvider.LoadCertificate(StoreName.My, StoreLocation.CurrentUser, "test")[0]);

            byte[] data = encription.EncryptText("Hello world!");

            Console.WriteLine(BitConverter.ToString(data));

            string text = encription.DecryptText(data);

            Console.WriteLine(text);
            Console.ReadLine();
        }

        static void RsaStreamTest()
        {

            using (var random = new RNGCryptoServiceProvider())
            {
                var key = new byte[16];
                random.GetBytes(key);

                using (Stream encrypted = new MemoryStream())
                {
                    using (MemoryStream original = new MemoryStream(AesEncription.StringToBytes("Hello world!")))
                    {
                        AesEncription.Encrypt1(original, encrypted, key);

                        string decrypted = AesEncription.DecryptText(((MemoryStream)encrypted).ToArray(), key);


                        // X509KeyStorageFlags

                    }
                }


            }
        }

        static void LoadCertAndKeyType()
        {
            X509Certificate2 cert = EncriptionProvider.LoadCertificate(StoreName.My, StoreLocation.CurrentUser, "test")[0];
            KeyType keyType = EncriptionProvider.GetCertificateType(cert);
        }
    }
}
