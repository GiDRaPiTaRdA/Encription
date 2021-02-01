using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UnitTestTools
{
    public static class Assertions
    {
        public static void CompareHash(Stream streamData1, Stream streamData2)
        {
            Md5HashProvider hashProvider = new Md5HashProvider();

            ulong originalHash = hashProvider.Hash(streamData1);
            ulong decryptedHash = hashProvider.Hash(streamData2);

            Assert.IsTrue(originalHash == decryptedHash, $"Hash does not match, streamData1: {originalHash} streamData2: {decryptedHash}");
        }

        public static void CompareHash(byte[] data1, byte[] data2)
        {
            Md5HashProvider hashProvider = new Md5HashProvider();

            ulong originalHash = hashProvider.Hash(data1);
            ulong decryptedHash = hashProvider.Hash(data2);

            Assert.IsTrue(originalHash == decryptedHash, $"Hash does not match, data1: {originalHash} data2: {decryptedHash}");
        }
    }
}
