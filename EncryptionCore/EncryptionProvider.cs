using System;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using EncryptionCore.Data;

namespace EncryptionCore
{
    public abstract class EncryptionProvider : CertificateBasedEncription
    {
        protected EncryptionProvider(X509Certificate2 cert) : base(cert){}

        public abstract byte[] Encrypt(byte[] dataToEncrypt);

        public abstract byte[] Decrypt(byte[] encryptedData);

        public byte[] EncryptText(string text) =>
            this.Encrypt(StringToBytes(text));

        public string DecryptText(byte[] ecryptedData) =>
            BytesToString(this.Decrypt(ecryptedData));

        public bool CanDecrypt() => cert.HasPrivateKey;


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

        public static void ImportCertificate()
        {
            X509Certificate2 cert = new X509Certificate2("a.pfx", "password", X509KeyStorageFlags.MachineKeySet);
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            store.Add(cert);
        }
    }
}
