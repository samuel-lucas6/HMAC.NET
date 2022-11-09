using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using HMACDotNet;

namespace HMACDotNetTests;

[TestClass]
public class HMACTests
{
    // https://www.rfc-editor.org/rfc/rfc4231#section-4
    public static IEnumerable<object[]> Rfc4231Sha256()
    {
        yield return new object[] { Hmac.HashFunction.SHA256, "4869205468657265", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" };
        yield return new object[] { Hmac.HashFunction.SHA256, "7768617420646f2079612077616e7420666f72206e6f7468696e673f", "4a656665", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" };
        yield return new object[] { Hmac.HashFunction.SHA256, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe" };
        yield return new object[] { Hmac.HashFunction.SHA256, "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "0102030405060708090a0b0c0d0e0f10111213141516171819", "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b" };
        // Truncated to 128 bits
        // yield return new object[] { Hmac.HashFunction.SHA256, "546573742057697468205472756e636174696f6e", "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "a3b6167473100ee06e0c796c2955552b" };
        yield return new object[] { Hmac.HashFunction.SHA256, "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54" };
        yield return new object[] { Hmac.HashFunction.SHA256, "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2" };
    }
    
    // https://www.rfc-editor.org/rfc/rfc4868#section-2.7.2.1
    public static IEnumerable<object[]> Rfc4868Sha256()
    {
        yield return new object[] { Hmac.HashFunction.SHA256, "4869205468657265", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7" };
        yield return new object[] { Hmac.HashFunction.SHA256, "7768617420646f2079612077616e7420666f72206e6f7468696e673f", "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665", "167f928588c5cc2eef8e3093caa0e87c9ff566a14794aa61648d81621a2a40c6" };
        yield return new object[] { Hmac.HashFunction.SHA256, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "cdcb1220d1ecccea91e53aba3092f962e549fe6ce9ed7fdc43191fbde45c30b0" };
        yield return new object[] { Hmac.HashFunction.SHA256, "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", "372efcf9b40b35c2115b1346903d2ef42fced46f0846e7257bb156d3d7b30d3f" };
    }
    
    // https://www.rfc-editor.org/rfc/rfc4231#section-4
    public static IEnumerable<object[]> Rfc4231Sha384()
    {
        yield return new object[] { Hmac.HashFunction.SHA384, "4869205468657265", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6" };
        yield return new object[] { Hmac.HashFunction.SHA384, "7768617420646f2079612077616e7420666f72206e6f7468696e673f", "4a656665", "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649" };
        yield return new object[] { Hmac.HashFunction.SHA384, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27" };
        yield return new object[] { Hmac.HashFunction.SHA384, "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "0102030405060708090a0b0c0d0e0f10111213141516171819", "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb" };
        // Truncated to 128 bits
        // yield return new object[] { Hmac.HashFunction.SHA384, "546573742057697468205472756e636174696f6e", "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "3abf34c3503b2a23a46efc619baef897" };
        yield return new object[] { Hmac.HashFunction.SHA384, "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952" };
        yield return new object[] { Hmac.HashFunction.SHA384, "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e" };
    }
    
    // https://www.rfc-editor.org/rfc/rfc4868#section-2.7.2.2
    public static IEnumerable<object[]> Rfc4868Sha384()
    {
        yield return new object[] { Hmac.HashFunction.SHA384, "4869205468657265", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "b6a8d5636f5c6a7224f9977dcf7ee6c7fb6d0c48cbdee9737a959796489bddbc4c5df61d5b3297b4fb68dab9f1b582c2" };
        yield return new object[] { Hmac.HashFunction.SHA384, "7768617420646f2079612077616e7420666f72206e6f7468696e673f", "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665", "2c7353974f1842fd66d53c452ca42122b28c0b594cfb184da86a368e9b8e16f5349524ca4e82400cbde0686d403371c9" };
        yield return new object[] { Hmac.HashFunction.SHA384, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "809f439be00274321d4a538652164b53554a508184a0c3160353e3428597003d35914a18770f9443987054944b7c4b4a" };
        yield return new object[] { Hmac.HashFunction.SHA384, "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200a0b0c0d0e0f10111213141516171819", "5b540085c6e6358096532b2493609ed1cb298f774f87bb5c2ebf182c83cc7428707fb92eab2536a5812258228bc96687" };
    }
    
    // https://www.rfc-editor.org/rfc/rfc4231#section-4
    public static IEnumerable<object[]> Rfc4231Sha512()
    {
        yield return new object[] { Hmac.HashFunction.SHA512, "4869205468657265", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854" };
        yield return new object[] { Hmac.HashFunction.SHA512, "7768617420646f2079612077616e7420666f72206e6f7468696e673f", "4a656665", "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737" };
        yield return new object[] { Hmac.HashFunction.SHA512, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb" };
        yield return new object[] { Hmac.HashFunction.SHA512, "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "0102030405060708090a0b0c0d0e0f10111213141516171819", "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd" };
        // Truncated to 128 bits
        // yield return new object[] { Hmac.HashFunction.SHA512, "546573742057697468205472756e636174696f6e", "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "415fad6271580a531d4179bc891d87a6" };
        yield return new object[] { Hmac.HashFunction.SHA512, "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598" };
        yield return new object[] { Hmac.HashFunction.SHA512, "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58" };
    }
    
    // https://www.rfc-editor.org/rfc/rfc4868#section-2.7.2.3
    public static IEnumerable<object[]> Rfc4868Sha512()
    {
        yield return new object[] { Hmac.HashFunction.SHA512, "4869205468657265", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "637edc6e01dce7e6742a99451aae82df23da3e92439e590e43e761b33e910fb8ac2878ebd5803f6f0b61dbce5e251ff8789a4722c1be65aea45fd464e89f8f5b" };
        yield return new object[] { Hmac.HashFunction.SHA512, "7768617420646f2079612077616e7420666f72206e6f7468696e673f", "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665", "cb370917ae8a7ce28cfd1d8f4705d6141c173b2a9362c15df235dfb251b154546aa334ae9fb9afc2184932d8695e397bfa0ffb93466cfcceaae38c833b7dba38" };
        yield return new object[] { Hmac.HashFunction.SHA512, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "2ee7acd783624ca9398710f3ee05ae41b9f9b0510c87e49e586cc9bf961733d8623c7b55cebefccf02d5581acc1c9d5fb1ff68a1de45509fbe4da9a433922655" };
        yield return new object[] { Hmac.HashFunction.SHA512, "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40", "5e6688e5a3daec826ca32eaea224eff5e700628947470e13ad01302561bab108b8c48cbc6b807dcfbd850521a685babc7eae4a2a2e660dc0e86b931d65503fd2" };
    }
    
    [TestMethod]
    [DynamicData(nameof(Rfc4231Sha256), DynamicDataSourceType.Method)]
    [DynamicData(nameof(Rfc4868Sha256), DynamicDataSourceType.Method)]
    [DynamicData(nameof(Rfc4231Sha384), DynamicDataSourceType.Method)]
    [DynamicData(nameof(Rfc4868Sha384), DynamicDataSourceType.Method)]
    [DynamicData(nameof(Rfc4231Sha512), DynamicDataSourceType.Method)]
    [DynamicData(nameof(Rfc4868Sha512), DynamicDataSourceType.Method)]
    public void TestVectors(Hmac.HashFunction hashFunction, string message, string key, string tag)
    {
        byte[] m = Convert.FromHexString(message);
        byte[] k = Convert.FromHexString(key);
        
        byte[] t = Hmac.ComputeTag(m, k, hashFunction);
        
        Assert.AreEqual(tag, Convert.ToHexString(t).ToLower());
    }
}