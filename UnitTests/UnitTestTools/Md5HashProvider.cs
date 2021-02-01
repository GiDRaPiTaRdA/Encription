using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace UnitTestTools
{
    public class Md5HashProvider
    {
        public ulong Hash(Stream stream)
        {
            byte[] fileHash;

            using (MD5 md5 = MD5.Create())
            {
                fileHash = md5.ComputeHash(stream);
            }

            return BitConverter.ToUInt64(fileHash, 0);
        }

        public ulong Hash(byte[] bytes)
        {
            byte[] fileHash;

            using (MD5 md5 = MD5.Create())
            {
                fileHash = md5.ComputeHash(bytes);
            }

            return BitConverter.ToUInt64(fileHash, 0);
        }
    }
}
