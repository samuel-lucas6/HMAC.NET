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

using System.Security.Cryptography;

namespace HMACDotNet;

public static class Hmac
{
    public enum HashFunction
    {
        SHA256 = 32,
        SHA384 = 48,
        SHA512 = 64
    }
    
    public static byte[] ComputeTag(byte[] message, byte[] key, HashFunction hashFunction)
    {
        if (message == null) { throw new ArgumentNullException(nameof(message), $"{nameof(message)} cannot be null."); }
        if (key == null) { throw new ArgumentNullException(nameof(key), $"{nameof(key)} cannot be null."); }
        int blockSize = hashFunction == HashFunction.SHA256 ? 64 : 128;
        var ipad = new byte[blockSize];
        for (int i = 0; i < ipad.Length; i++)
        {
            ipad[i] = 0x36;
        }
        var opad = new byte[blockSize];
        for (int i = 0; i < opad.Length; i++)
        {
            opad[i] = 0x5C;
        }
        using var hashAlgorithm = CreateHashFunction(hashFunction);
        var paddedKey = new byte[blockSize];
        Array.Copy(key.Length > paddedKey.Length ? hashAlgorithm.ComputeHash(key) : key, paddedKey, key.Length > paddedKey.Length ? hashAlgorithm.HashSize / 8 : key.Length);
        for (int i = 0; i < ipad.Length; i++)
        {
            ipad[i] ^= paddedKey[i];
        }
        var keyConcatMessage = new byte[ipad.Length + message.Length];
        Array.Copy(ipad, keyConcatMessage, ipad.Length);
        Array.Copy(message, sourceIndex: 0, keyConcatMessage, destinationIndex: ipad.Length, message.Length);
        byte[] innerHash = hashAlgorithm.ComputeHash(keyConcatMessage);
        for (int i = 0; i < opad.Length; i++)
        {
            opad[i] ^= paddedKey[i];
        }
        var keyConcatHash = new byte[opad.Length + innerHash.Length];
        Array.Copy(opad, keyConcatHash, opad.Length);
        Array.Copy(innerHash, sourceIndex: 0, keyConcatHash, destinationIndex: opad.Length, innerHash.Length);
        return hashAlgorithm.ComputeHash(keyConcatHash);
    }

    private static HashAlgorithm CreateHashFunction(HashFunction hashFunction)
    {
        if (hashFunction == HashFunction.SHA256) { return SHA256.Create(); }
        if (hashFunction == HashFunction.SHA384) { return SHA384.Create(); }
        return SHA512.Create();
    }
}