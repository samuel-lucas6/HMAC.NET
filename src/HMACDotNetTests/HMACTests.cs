/*
    HMAC.NET: A .NET implementation of HMAC.
    Copyright (c) 2022 Samuel Lucas
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography;
using HMACDotNet;

namespace HMACDotNetTests
{
    [TestClass]
    public class HMACTests
    {
        // Test Vectors from RFC 4868: https://www.rfc-editor.org/rfc/rfc4868#section-2.7.2
        // The RFC 4231 Test Vectors seem to be borked as they don't match the .NET HMAC implementation
        // The NIST Test Vectors seem to be using truncated outputs
        // Some additional tests were added (e.g. to test different key sizes)

        [TestMethod]
        public void SHA256TestVector1()
        {
            byte[] key = Convert.FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            byte[] data = Convert.FromHexString("4869205468657265");
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA256);
            byte[] expectedTag = Convert.FromHexString("198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7");
            byte[] expectedTag2 = HMACSHA256.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag2));
        }

        [TestMethod]
        public void SHA256TestVector2()
        {
            byte[] key = Convert.FromHexString("4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665");
            byte[] data = Convert.FromHexString("7768617420646f2079612077616e7420666f72206e6f7468696e673f");
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA256);
            byte[] expectedTag = Convert.FromHexString("167f928588c5cc2eef8e3093caa0e87c9ff566a14794aa61648d81621a2a40c6");
            byte[] expectedTag2 = HMACSHA256.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag2));
        }

        [TestMethod]
        public void SHA256TestVector3()
        {
            byte[] key = Convert.FromHexString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            byte[] data = Convert.FromHexString("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA256);
            byte[] expectedTag = Convert.FromHexString("cdcb1220d1ecccea91e53aba3092f962e549fe6ce9ed7fdc43191fbde45c30b0");
            byte[] expectedTag2 = HMACSHA256.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag2));
        }

        [TestMethod]
        public void SHA256TestVector4()
        {
            byte[] key = Convert.FromHexString("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
            byte[] data = Convert.FromHexString("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA256);
            byte[] expectedTag = Convert.FromHexString("372efcf9b40b35c2115b1346903d2ef42fced46f0846e7257bb156d3d7b30d3f");
            byte[] expectedTag2 = HMACSHA256.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag2));
        }

        [TestMethod]
        public void SHA256TestVector5()
        {
            byte[] key = Convert.FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            byte[] data = Convert.FromHexString("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA256);
            byte[] expectedTag = HMACSHA256.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
        }

        [TestMethod]
        public void SHA256TestVector6()
        {
            byte[] key = Array.Empty<byte>();
            byte[] data = Convert.FromHexString("7768617420646f2079612077616e7420666f72206e6f7468696e673f");
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA256);
            byte[] expectedTag = HMACSHA256.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
        }

        [TestMethod]
        public void SHA256TestVector7()
        {
            byte[] key = Convert.FromHexString("74657374");
            var data = Array.Empty<byte>();
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA256);
            byte[] expectedTag = HMACSHA256.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
        }

        [TestMethod]
        public void SHA256TestVector8()
        {
            byte[] key = Array.Empty<byte>();
            var data = Array.Empty<byte>();
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA256);
            byte[] expectedTag = HMACSHA256.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
        }

        [TestMethod]
        public void SHA384TestVector1()
        {
            byte[] key = Convert.FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            byte[] data = Convert.FromHexString("4869205468657265");
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA384);
            byte[] expectedTag = Convert.FromHexString("b6a8d5636f5c6a7224f9977dcf7ee6c7fb6d0c48cbdee9737a959796489bddbc4c5df61d5b3297b4fb68dab9f1b582c2");
            byte[] expectedTag2 = HMACSHA384.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag2));
        }

        [TestMethod]
        public void SHA384TestVector2()
        {
            byte[] key = Convert.FromHexString("4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665");
            byte[] data = Convert.FromHexString("7768617420646f2079612077616e7420666f72206e6f7468696e673f");
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA384);
            byte[] expectedTag = Convert.FromHexString("2c7353974f1842fd66d53c452ca42122b28c0b594cfb184da86a368e9b8e16f5349524ca4e82400cbde0686d403371c9");
            byte[] expectedTag2 = HMACSHA384.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag2));
        }

        [TestMethod]
        public void SHA384TestVector3()
        {
            byte[] key = Convert.FromHexString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            byte[] data = Convert.FromHexString("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA384);
            byte[] expectedTag = Convert.FromHexString("809f439be00274321d4a538652164b53554a508184a0c3160353e3428597003d35914a18770f9443987054944b7c4b4a");
            byte[] expectedTag2 = HMACSHA384.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag2));
        }

        [TestMethod]
        public void SHA384TestVector4()
        {
            byte[] key = Convert.FromHexString("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200a0b0c0d0e0f10111213141516171819");
            byte[] data = Convert.FromHexString("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA384);
            byte[] expectedTag = Convert.FromHexString("5b540085c6e6358096532b2493609ed1cb298f774f87bb5c2ebf182c83cc7428707fb92eab2536a5812258228bc96687");
            byte[] expectedTag2 = HMACSHA384.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag2));
        }

        [TestMethod]
        public void SHA384TestVector5()
        {
            byte[] key = Convert.FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            byte[] data = Convert.FromHexString("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA384);
            byte[] expectedTag = HMACSHA384.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
        }

        [TestMethod]
        public void SHA384TestVector6()
        {
            byte[] key = Array.Empty<byte>();
            byte[] data = Convert.FromHexString("7768617420646f2079612077616e7420666f72206e6f7468696e673f");
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA384);
            byte[] expectedTag = HMACSHA384.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
        }

        [TestMethod]
        public void SHA384TestVector7()
        {
            byte[] key = Convert.FromHexString("74657374");
            var data = Array.Empty<byte>();
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA384);
            byte[] expectedTag = HMACSHA384.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
        }

        [TestMethod]
        public void SHA384TestVector8()
        {
            byte[] key = Array.Empty<byte>();
            var data = Array.Empty<byte>();
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA384);
            byte[] expectedTag = HMACSHA384.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
        }


        [TestMethod]
        public void SHA512TestVector1()
        {
            byte[] key = Convert.FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            byte[] data = Convert.FromHexString("4869205468657265");
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA512);
            byte[] expectedTag = Convert.FromHexString("637edc6e01dce7e6742a99451aae82df23da3e92439e590e43e761b33e910fb8ac2878ebd5803f6f0b61dbce5e251ff8789a4722c1be65aea45fd464e89f8f5b");
            byte[] expectedTag2 = HMACSHA512.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag2));
        }

        [TestMethod]
        public void SHA512TestVector2()
        {
            byte[] key = Convert.FromHexString("4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665");
            byte[] data = Convert.FromHexString("7768617420646f2079612077616e7420666f72206e6f7468696e673f");
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA512);
            byte[] expectedTag = Convert.FromHexString("cb370917ae8a7ce28cfd1d8f4705d6141c173b2a9362c15df235dfb251b154546aa334ae9fb9afc2184932d8695e397bfa0ffb93466cfcceaae38c833b7dba38");
            byte[] expectedTag2 = HMACSHA512.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag2));
        }

        [TestMethod]
        public void SHA512TestVector3()
        {
            byte[] key = Convert.FromHexString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            byte[] data = Convert.FromHexString("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA512);
            byte[] expectedTag = Convert.FromHexString("2ee7acd783624ca9398710f3ee05ae41b9f9b0510c87e49e586cc9bf961733d8623c7b55cebefccf02d5581acc1c9d5fb1ff68a1de45509fbe4da9a433922655");
            byte[] expectedTag2 = HMACSHA512.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag2));
        }

        [TestMethod]
        public void SHA512TestVector4()
        {
            byte[] key = Convert.FromHexString("0a0b0c0d0e0f101112131415161718190102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
            byte[] data = Convert.FromHexString("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA512);
            // This test vector is actually wrong in RFC 4868 - checked CyberChef and the .NET implementation
            byte[] expectedTag = Convert.FromHexString("e499c6c8ab9a2039d4777ceba77f0baf7b752d7c9cd738fad9d5a752381fd72f6bdc69589d24c5fac58179637654c3d1a2cdc9a326c9ed3c20df0119732144b2");
            byte[] expectedTag2 = HMACSHA512.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag2));
        }

        [TestMethod]
        public void SHA512TestVector5()
        {
            byte[] key = Convert.FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            byte[] data = Convert.FromHexString("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA512);
            byte[] expectedTag = HMACSHA512.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
        }

        [TestMethod]
        public void SHA512TestVector6()
        {
            byte[] key = Array.Empty<byte>();
            byte[] data = Convert.FromHexString("7768617420646f2079612077616e7420666f72206e6f7468696e673f");
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA512);
            byte[] expectedTag = HMACSHA512.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
        }

        [TestMethod]
        public void SHA512TestVector7()
        {
            byte[] key = Convert.FromHexString("74657374");
            var data = Array.Empty<byte>();
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA512);
            byte[] expectedTag = HMACSHA512.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
        }

        [TestMethod]
        public void SHA512TestVector8()
        {
            byte[] key = Array.Empty<byte>();
            var data = Array.Empty<byte>();
            byte[] computedTag = Hmac.ComputeTag(data, key, Hmac.HashFunction.SHA512);
            byte[] expectedTag = HMACSHA512.HashData(key, data);
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(computedTag, expectedTag));
        }
    }
}