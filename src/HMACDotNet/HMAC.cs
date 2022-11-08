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
        for (int i = 0; i < ipad.Length; i++) {
            ipad[i] = 0x36;
        }
        var opad = new byte[blockSize];
        for (int i = 0; i < opad.Length; i++) {
            opad[i] = 0x5C;
        }
        var incrementalHash = IncrementalHash.CreateHash(GetHashAlgorithmName(hashFunction));
        var paddedKey = new byte[blockSize];
        if (key.Length > paddedKey.Length) {
            incrementalHash.AppendData(key);
            Array.Copy(incrementalHash.GetHashAndReset(), paddedKey, incrementalHash.HashLengthInBytes);
        }
        else {
            Array.Copy(key, paddedKey, key.Length);
        }
        for (int i = 0; i < ipad.Length; i++) {
            ipad[i] ^= paddedKey[i];
        }
        incrementalHash.AppendData(ipad);
        incrementalHash.AppendData(message);
        byte[] innerHash = incrementalHash.GetHashAndReset();
        for (int i = 0; i < opad.Length; i++) {
            opad[i] ^= paddedKey[i];
        }
        incrementalHash.AppendData(opad);
        incrementalHash.AppendData(innerHash);
        return incrementalHash.GetHashAndReset();
    }

    private static HashAlgorithmName GetHashAlgorithmName(HashFunction hashFunction)
    {
        return hashFunction switch
        {
            HashFunction.SHA256 => HashAlgorithmName.SHA256,
            HashFunction.SHA384 => HashAlgorithmName.SHA384,
            _ => HashAlgorithmName.SHA512
        };
    }
}