using EncriptionCore;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Encription
{
    class Program
    {
        static void Main(string[] args)
        {
            EncriptionProvider client = new RsaEncriptionProvider(EncriptionProvider.ReadCert(ReadFile(@"cert\EgyptAC.pfx"), "Edrfo2018"));
            EncriptionProvider sender = new RsaEncriptionProvider(EncriptionProvider.ReadCert(ReadFile(@"cert\EgyptAC.cer")));

            byte[] data = sender.EncryptText("test");

            Console.WriteLine(BitConverter.ToString(data));

            string text = client.DecryptText(data);

            Console.WriteLine(text);
            Console.ReadLine();

            test1();

            Console.ReadKey();
        }

        private static byte[] ReadFile(string fileName)
        {
            using (FileStream f = new FileStream(fileName, FileMode.Open, FileAccess.Read))
            {
                int size = (int)f.Length;
                byte[] data = new byte[size];
                size = f.Read(data, 0, size);
                return data;
            }
        }



        static void test() 
        {
            string original = "Hello world!";

            using (var random = new RNGCryptoServiceProvider())
            {
                var key = new byte[16];
                random.GetBytes(key);

                byte[] encrypted = AesEncription.EncryptText(original,key);

                string decrypted = AesEncription.DecryptText(encrypted, key);

                //Display the original data and the decrypted data.
                Console.WriteLine("Original:   {0}", original);
                Console.WriteLine("Key:   {0}", Convert.ToBase64String(key));
                Console.WriteLine("Encrypted (b64-encode): {0}", Convert.ToBase64String(encrypted));
                Console.WriteLine("Round Trip: {0}", decrypted);
              
            }
        }

        static void test1()
        {

            using (var random = new RNGCryptoServiceProvider())
            {
                var key = new byte[16];
                random.GetBytes(key);

                using (Stream encrypted = new MemoryStream())
                {
                    using (MemoryStream original = new MemoryStream(AesEncription.StringToBytes("Hello world!")))
                    {
                        AesEncription.Encrypt1(original, in encrypted, key);

                        string decrypted = AesEncription.DecryptText(((MemoryStream)encrypted).ToArray(), key);



                      
                    }
                }


            }
        }
    }
}
