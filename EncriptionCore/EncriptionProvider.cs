using System;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using EncriptionCore.Data;

namespace EncriptionCore
{
    public abstract class EncriptionProvider
    {
        protected X509Certificate2 cert;

        public EncriptionProvider(X509Certificate2 cert)
        {
            this.cert = cert;
        }

        public abstract byte[] Encrypt(byte[] dataToEncrypt);

        public abstract byte[] Decrypt(byte[] encryptedData);

        public byte[] EncryptText(string text) =>
            this.Encrypt(StringToBytes(text));

        public string DecryptText(byte[] ecryptedData) =>
            BytesToString(this.Decrypt(ecryptedData));

        public bool CanDecrypt() => cert.HasPrivateKey;




        public static bool CanDecrypt(X509Certificate2 cert) => cert.HasPrivateKey;

        public static X509Certificate2 ReadCert(byte[] certData)
        {
            X509Certificate2 x509 = new X509Certificate2();

            x509.Import(certData);
            return x509;
        }

        public static X509Certificate2 ReadCert(byte[] certData, string password)
        {
            X509Certificate2 x509 = new X509Certificate2();

            x509.Import(certData, password, X509KeyStorageFlags.DefaultKeySet);
            return x509;
        }

        public static void ViewCert(X509Certificate2 x509, Action<string> output)
        {
            //Print to console information contained in the certificate.
            output?.Invoke(string.Format("{0}Subject: {1}{0}", Environment.NewLine, x509.Subject));
            output?.Invoke(string.Format("{0}Issuer: {1}{0}", Environment.NewLine, x509.Issuer));
            output?.Invoke(string.Format("{0}Version: {1}{0}", Environment.NewLine, x509.Version));
            output?.Invoke(string.Format("{0}Valid Date: {1}{0}", Environment.NewLine, x509.NotBefore));
            output?.Invoke(string.Format("{0}Expiry Date: {1}{0}", Environment.NewLine, x509.NotAfter));
            output?.Invoke(string.Format("{0}Thumbprint: {1}{0}", Environment.NewLine, x509.Thumbprint));
            output?.Invoke(string.Format("{0}Serial Number: {1}{0}", Environment.NewLine, x509.SerialNumber));
            output?.Invoke(string.Format("{0}Friendly Name: {1}{0}", Environment.NewLine, x509.PublicKey.Oid.FriendlyName));
            output?.Invoke(string.Format("{0}Public Key Format: {1}{0}", Environment.NewLine, x509.PublicKey.EncodedKeyValue.Format(true)));
            output?.Invoke(string.Format("{0}Raw Data Length: {1}{0}", Environment.NewLine, x509.RawData.Length));
            output?.Invoke(string.Format("{0}Certificate to string: {1}{0}", Environment.NewLine, x509.ToString(true)));
            output?.Invoke(string.Format("{0}Certificate to XML String: {1}{0}", Environment.NewLine, x509.PublicKey.Key.ToXmlString(false)));
        }

        protected static string BytesToString(byte[] bytes)
        {
            UnicodeEncoding byteConverter = new UnicodeEncoding();

            string text = byteConverter.GetString(bytes);

            return text;
        }

        protected static byte[] StringToBytes(string text)
        {
            UnicodeEncoding byteConverter = new UnicodeEncoding();

            byte[] bytes = byteConverter.GetBytes(text);

            return bytes;
        }

        public static KeyType GetCertificateType(X509Certificate2 cert)
        {
            const string RSA = "1.2.840.113549.1.1.1";
            const string DSA = "1.2.840.10040.4.1";
            const string ECC = "1.2.840.10045.2.1";

            switch (cert.PublicKey.Oid.Value)
            {
                case RSA:
                    return KeyType.RSA;
                case DSA:
                    return KeyType.DSA;
                case ECC:
                    return KeyType.ECC;
                default:
                    throw new NotSupportedException();
            }
        }

        public static X509Certificate2Collection LoadCertificate(StoreName storeName, StoreLocation location, string subjectName)
        {
            X509Store store = null;
            try
            {
                store = new X509Store(storeName, location);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindBySubjectName, subjectName, false);

                return certs;
            }
            finally
            {
                store?.Close();
            }


        }
    }
}
