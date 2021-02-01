using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionCore
{
    public class AesEncryption
    {
        private static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key)
        {
            byte[] encrypted;
            byte[] IV;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;

                aesAlg.GenerateIV();
                IV = aesAlg.IV;

                aesAlg.Mode = CipherMode.CBC;

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption. 
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            var combinedIvCt = new byte[IV.Length + encrypted.Length];
            Array.Copy(IV, 0, combinedIvCt, 0, IV.Length);
            Array.Copy(encrypted, 0, combinedIvCt, IV.Length, encrypted.Length);

            // Return the encrypted bytes from the memory stream. 
            return combinedIvCt;

        }

        private static string DecryptStringFromBytes_Aes(byte[] cipherTextCombined, byte[] Key)
        {

            // Declare the string used to hold 
            // the decrypted text. 
            string plaintext = null;

            // Create an Aes object 
            // with the specified key and IV. 
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;

                byte[] IV = new byte[aesAlg.BlockSize / 8];
                byte[] cipherText = new byte[cipherTextCombined.Length - IV.Length];

                Array.Copy(cipherTextCombined, IV, IV.Length);
                Array.Copy(cipherTextCombined, IV.Length, cipherText, 0, cipherText.Length);

                aesAlg.IV = IV;

                aesAlg.Mode = CipherMode.CBC;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption. 
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;

        }


        public static byte[] EncryptText(string data, byte[] key) =>
            Encrypt(StringToBytes(data), key);

        public static string DecryptText(byte[] cipherTextCombined, byte[] key) =>
            BytesToString(Decrypt(cipherTextCombined, key));


        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            using (MemoryStream dataStream = new MemoryStream(data))
            {
                using (MemoryStream encryptStream = new MemoryStream())
                {
                    EncryptStream(dataStream, encryptStream, key);

                    return encryptStream.ToArray(); ;
                }
            }
        }

        public static byte[] Decrypt(byte[] encriptedData, byte[] key)
        {
            using (MemoryStream dataStream = new MemoryStream())
            {
                using (MemoryStream encryptStream = new MemoryStream(encriptedData))
                {
                    DecryptStream(encryptStream, dataStream, key);

                    return dataStream.ToArray();
                }
            }
        }


        public static byte[] EncryptTest(byte[] data, byte[] key)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.GenerateIV();

                aesAlg.Mode = CipherMode.CBC;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream encryptStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(encryptStream, encryptor, CryptoStreamMode.Write, leaveOpen: true))
                    {
                        encryptStream.Write(aesAlg.IV, 0, aesAlg.IV.Length);    // IV
                        cryptoStream.Write(data, 0, data.Length);               // encrypt=
                    }

                    return encryptStream.ToArray();
                }
            }
        }

        public static byte[] DecryptTest(byte[] data, byte[] key)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;

                byte[] IV = new byte[aesAlg.BlockSize / 8];
                byte[] cipherText = new byte[data.Length - IV.Length];

                Array.Copy(data, IV, IV.Length);
                Array.Copy(data, IV.Length, cipherText, 0, cipherText.Length);

                aesAlg.IV = IV;

                aesAlg.Mode = CipherMode.CBC;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);


                using (MemoryStream dataStream = new MemoryStream())
                {
                    using (MemoryStream encryptedStream = new MemoryStream(cipherText))
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(encryptedStream, decryptor, CryptoStreamMode.Read, leaveOpen: false))
                        {
                            cryptoStream.CopyTo(dataStream);
                            return dataStream.ToArray();
                        }
                    }
                }
            }
        }


        public static void EncryptStream(Stream dataStream, Stream encryptStream, byte[] key)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.GenerateIV();

                aesAlg.Mode = CipherMode.CBC;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (CryptoStream cryptoStream = new CryptoStream(encryptStream, encryptor, CryptoStreamMode.Write, leaveOpen: true))
                {
                    encryptStream.Write(aesAlg.IV, 0, aesAlg.IV.Length);    // IV
                    dataStream.CopyTo(cryptoStream);                        // encrypt
                    //cryptoStream.FlushFinalBlock();
                }
            }
        }

        public static void DecryptStream(Stream encryptedStream, Stream dataStream, byte[] Key)
        {
            // Create an Aes object 
            // with the specified key and IV. 
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;

                byte[] IV = new byte[aesAlg.BlockSize / 8];

                //encryptedStream.Position = 0;
                encryptedStream.Read(buffer: IV, offset: 0, count: IV.Length);     // obtain IV  

                aesAlg.IV = IV;

                aesAlg.Mode = CipherMode.CBC;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                //encryptedStream.Position = IV.Length;
                using (CryptoStream cryptoStream = new CryptoStream(encryptedStream, decryptor, CryptoStreamMode.Read, leaveOpen: false))
                {
                    cryptoStream.CopyTo(dataStream);                               // decrypt
                    //cryptoStream.FlushFinalBlock();
                }
            }
        }


        public static string BytesToString(byte[] bytes)
        {
            UnicodeEncoding byteConverter = new UnicodeEncoding();

            string text = byteConverter.GetString(bytes);

            return text;
        }

        public static byte[] StringToBytes(string text)
        {
            UnicodeEncoding byteConverter = new UnicodeEncoding();

            byte[] bytes = byteConverter.GetBytes(text);

            return bytes;
        }

        public static byte[] GenerateKey()
        {
            // Generate key
            byte[] key;
            using (RNGCryptoServiceProvider random = new RNGCryptoServiceProvider())
            {
                key = new byte[16];
                random.GetBytes(key);
            }

            return key;
        }
    }
}
