using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace EncriptionCore
{
    public class RsaEncriptionProvider : EncriptionProvider
    {
        private RSAEncryptionPadding padding;

        public RsaEncriptionProvider(X509Certificate2 cert):this(cert, RSAEncryptionPadding.OaepSHA1) { }

        public RsaEncriptionProvider(X509Certificate2 cert, RSAEncryptionPadding padding):base(cert)
        {
            this.padding = padding;
        }

        public override byte[] Encrypt(byte[] dataToEncrypt) =>
            Encrypt(cert, dataToEncrypt, padding);

        public override byte[] Decrypt(byte[] encryptedData) =>
            Decrypt(cert, encryptedData, padding);


        public static byte[] Encrypt(X509Certificate2 cert, byte[] data, RSAEncryptionPadding padding)
        {
            // GetRSAPublicKey returns an object with an independent lifetime, so it should be
            // handled via a using statement.
            using (RSA rsa = cert.GetRSAPublicKey())
            {
                // OAEP allows for multiple hashing algorithms, what was formermly just "OAEP" is
                // now OAEP-SHA1.
                return rsa.Encrypt(data, padding);
            }
        }

        public static byte[] Decrypt(X509Certificate2 cert, byte[] data, RSAEncryptionPadding padding)
        {
            byte[] decryptedData = null;

            if (CanDecrypt(cert))
            {
                // GetRSAPrivateKey returns an object with an independent lifetime, so it should be
                // handled via a using statement.
                using (RSA rsa = cert.GetRSAPrivateKey())
                {
                    decryptedData = rsa.Decrypt(data, padding);
                }
            }

            return decryptedData;
        }


        private static byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] encryptedData;
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {

                    //Import the RSA Key information. This only needs
                    //toinclude the public key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Encrypt the passed byte array and specify OAEP padding.  
                    //OAEP padding is only available on Microsoft Windows XP or
                    //later.  
                    encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
                }
                return encryptedData;
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }
        }

        private static byte[] RSADecrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] decryptedData;
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    //Import the RSA Key information. This needs
                    //to include the private key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Decrypt the passed byte array and specify OAEP padding.  
                    //OAEP padding is only available on Microsoft Windows XP or
                    //later.  
                    decryptedData = RSA.Decrypt(DataToDecrypt, DoOAEPPadding);
                }
                return decryptedData;
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());

                return null;
            }
        }

    }
}
