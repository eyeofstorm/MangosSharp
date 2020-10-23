//
//  Copyright (C) 2013-2020 getMaNGOS <https://getmangos.eu>
//  
//  This program is free software. You can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation. either version 2 of the License, or
//  (at your option) any later version.
//  
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY. Without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//  
//  You should have received a copy of the GNU General Public License
//  along with this program. If not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

using System;
using System.Collections;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using static System.Array;
using static System.Buffer;
using static System.Numerics.BigInteger;

namespace Mangos.Realm
{
    public sealed class AuthEngineClass
    {
        public static readonly byte[] CrcSalt = new byte[16];
        private static readonly Random Random = new Random();

        private byte[] _a;
        private readonly byte[] _b;
        public byte[] PublicB;
        public byte[] g;
        private readonly byte[] _k;
        // Private PublicK As Byte() = SS_Hash
        public byte[] M2;
        public readonly byte[] N;
        // Private Password As Byte()
        private byte[] _s;
        public readonly byte[] Salt;
        private byte[] _u;
        // Public CrcHash As Byte()
        private byte[] _username;
        public byte[] M1;
        public byte[] SsHash;
        private BigInteger _bna;
        private BigInteger _bNb;
        private BigInteger _bnPublicB;
        private BigInteger _bNg;
        private BigInteger _bNk;
        private BigInteger _bNn;
        private BigInteger _bns;
        private BigInteger _bnu;
        private BigInteger _bNv;
        private BigInteger _bNx;

        static AuthEngineClass()
        {
            if (CrcSalt != null) Random?.NextBytes(CrcSalt);
        }

        public AuthEngineClass()
        {
            var buffer1 = new byte[] { 7 };
            g = buffer1;
            N = new byte[] { 137, 75, 100, 94, 137, 225, 83, 91, 189, 173, 91, 139, 41, 6, 80, 83, 8, 1, 177, 142, 191, 191, 94, 143, 171, 60, 130, 135, 42, 62, 155, 183 };
            Salt = new byte[] { 173, 208, 58, 49, 210, 113, 20, 70, 117, 242, 112, 126, 80, 38, 182, 210, 241, 134, 89, 153, 118, 2, 80, 170, 185, 69, 224, 158, 221, 42, 163, 69 };
            var buffer2 = new byte[] { 3 };
            _k = buffer2;
            PublicB = new byte[32];
            _b = new byte[20];
        }

        private void CalculateB()
        {
            // Dim encoding1 As New UTF7Encoding
            Random.NextBytes(_b);
            var ptr1 = new BigInteger();
            var ptr2 = new BigInteger();
            var ptr3 = new BigInteger();
            // Dim ptr4 As IntPtr = BN_new("")
            Reverse(_b);
            _bNb = new BigInteger(_b, true, true);
            Reverse(_b);
            ptr1 = ModPow(_bNg, _bNb, _bNn);
            ptr2 = _bNk * _bNv;
            ptr3 = ptr1 + ptr2;
            _bnPublicB = ptr3 % _bNn;
            PublicB = _bnPublicB.ToByteArray(true, true);
            if (PublicB != null) Reverse(PublicB);
        }

        private void CalculateK()
        {
            using var algorithm1 = new SHA1Managed();
            var list1 = Split(_s) ?? throw new ArgumentNullException($"SplARG0it(_s)");
            if (list1.Count > 0) list1[0] = algorithm1.ComputeHash(list1[0] as byte[]);
            if (list1.Count > 1) list1[1] = algorithm1.ComputeHash(list1[1] as byte[]);

            if (list1.Count > 0) SsHash = Combine(list1[0] as byte[], (byte[])list1[1]);
        }

        public void CalculateM2(byte[] m1Loc)
        {
            if (m1Loc == null) throw new ArgumentNullException(nameof(m1Loc));
            if (m1Loc.Length == 0) throw new ArgumentException("Value cannot be an empty collection.", nameof(m1Loc));
            using var algorithm1 = new SHA1Managed();
            if (_a == null) throw new ArgumentNullException(nameof(_a));
            if (SsHash == null) throw new ArgumentNullException(nameof(SsHash));
            var buffer1 = new byte[_a.Length + m1Loc.Length + SsHash.Length];
            BlockCopy(_a, 0, buffer1, 0, _a.Length);
            BlockCopy(m1Loc, 0, buffer1, _a.Length, m1Loc.Length);
            BlockCopy(SsHash, 0, buffer1, _a.Length + m1Loc.Length, SsHash.Length);
            M2 = algorithm1.ComputeHash(buffer1);
        }

        private void CalculateS()
        {
            var ptr1 = new BigInteger();
            var ptr2 = new BigInteger();
            // Dim ptr3 As IntPtr = BN_new("")
            // Dim ptr4 As IntPtr = BN_new("")
            _bns = new BigInteger();
            _s = new byte[32];
            ptr1 = ModPow(_bNv, _bnu, _bNn);
            ptr2 = _bna * ptr1;
            _bns = ModPow(ptr2, _bNb, _bNn);
            _s = _bns.ToByteArray(true, true);
            if (_s != null) Reverse(_s);
            CalculateK();
        }

        public void CalculateU(byte[] a)
        {
            if (a == null) throw new ArgumentNullException(nameof(a));
            if (a.Length == 0) throw new ArgumentException("Value cannot be an empty collection.", nameof(a));
            _a = a;
            using var algorithm1 = new SHA1Managed();
            if (PublicB != null)
            {
                var buffer1 = new byte[a.Length + PublicB.Length];
                BlockCopy(a, 0, buffer1, 0, a.Length);
                BlockCopy(PublicB, 0, buffer1, a.Length, PublicB.Length);
                _u = algorithm1.ComputeHash(buffer1);
            }

            if (_u != null)
            {
                Reverse(_u);
                _bnu = new BigInteger(_u, true, true);
                Reverse(_u);
            }

            Reverse(a);
            _bna = new BigInteger(a, true, true);
            Reverse(a);
            CalculateS();
        }

        private void CalculateV()
        {
            _bNv = ModPow(_bNg, _bNx, _bNn);
            CalculateB();
        }

        public void CalculateX(byte[] username, byte[] pwHash)
        {
            if (username == null) throw new ArgumentNullException(nameof(username));
            if (pwHash == null) throw new ArgumentNullException(nameof(pwHash));
            if (username.Length == 0)
                throw new ArgumentException("Value cannot be an empty collection.", nameof(username));
            if (pwHash.Length == 0) throw new ArgumentException("Value cannot be an empty collection.", nameof(pwHash));
            _username = username;
            using var algorithm1 = new SHA1Managed();
            if (Salt != null)
            {
                var buffer5 = new byte[Salt.Length + 20];
                BlockCopy(pwHash, 0, buffer5, Salt.Length, 20);
                BlockCopy(Salt, 0, buffer5, 0, Salt.Length);
                var buffer3 = algorithm1.ComputeHash(buffer5);

                Reverse(buffer3);
                _bNx = new BigInteger(buffer3, true, true);
            }

            if (g != null)
            {
                Reverse(g);
                _bNg = new BigInteger(g, true, true);
                Reverse(g);
            }

            if (_k != null)
            {
                Reverse(_k);
                _bNk = new BigInteger(_k, true, true);
                Reverse(_k);
            }

            if (N != null)
            {
                Reverse(N);
                _bNn = new BigInteger(N, true, true);
                Reverse(N);
            }

            CalculateV();
        }

        public void CalculateM1()
        {
            using var algorithm1 = new SHA1Managed();
            var ngHash = new byte[20];
            if (N == null) return;
            var nHash = algorithm1.ComputeHash(N);
            if (g == null) return;
            var gHash = algorithm1.ComputeHash(g);
            if (_username == null) return;
            var userHash = algorithm1.ComputeHash(_username);
            var i = 0;
            for (; i <= 19; i++)
            {
                if (i >= 0 && ngHash.Length > i) ngHash[i] = (byte)(nHash[i] ^ gHash[i]);
            }
            var temp = Concat(ngHash, userHash) ?? throw new ArgumentNullException($"Concat(ngHash, userHash)");
            if (Salt != null) temp = Concat(temp, Salt);
            if (_a != null) temp = Concat(temp, _a);
            if (PublicB != null) temp = Concat(temp, PublicB);
            if (SsHash != null) temp = Concat(temp, SsHash);
            if (temp != null) M1 = algorithm1.ComputeHash(temp);
        }

        // Public Sub CalculateM1_Full()
        // Dim sha2 As New SHA1CryptoServiceProvider
        // Dim i As Byte = 0

        // 'Calc S1/S2
        // Dim s1 As Byte()
        // s1 = New Byte(16 - 1) {}
        // Dim s2 As Byte()
        // s2 = New Byte(16 - 1) {}
        // Do While (i < 16)
        // s1(i) = _s((i * 2))
        // s2(i) = _s(((i * 2) + 1))
        // i += 1
        // Loop

        // 'Calc SSHash
        // Dim s1Hash As Byte()
        // s1Hash = sha2.ComputeHash(s1)
        // Dim s2Hash As Byte()
        // s2Hash = sha2.ComputeHash(s2)
        // ReDim SsHash(32 - 1)
        // i = 0
        // Do While (i < 16)
        // SsHash((i * 2)) = s1Hash(i)
        // SsHash(((i * 2) + 1)) = s2Hash(i)
        // i += 1
        // Loop

        // 'Calc M1
        // Dim nHash As Byte()
        // nHash = sha2.ComputeHash(N)
        // Dim gHash As Byte()
        // gHash = sha2.ComputeHash(g)
        // Dim userHash As Byte()
        // userHash = sha2.ComputeHash(_Username)

        // Dim ngHash As Byte()
        // ngHash = New Byte(20 - 1) {}
        // i = 0
        // Do While (i < 20)
        // ngHash(i) = (nHash(i) Xor gHash(i))
        // i += 1
        // Loop

        // Dim temp As Byte() = Concat(ngHash, userHash)
        // temp = Concat(temp, Salt)
        // temp = Concat(temp, _a)
        // temp = Concat(temp, PublicB)
        // temp = Concat(temp, SsHash)
        // M1 = sha2.ComputeHash(temp)
        // End Sub

        private static byte[] Combine(IReadOnlyList<byte> bytes1, IReadOnlyList<byte> bytes2)
        {
            if (bytes1 == null) throw new ArgumentNullException(nameof(bytes1));
            if (bytes2 == null) throw new ArgumentNullException(nameof(bytes2));
            if (bytes1.Count == 0) throw new ArgumentException("Value cannot be an empty collection.", nameof(bytes1));
            if (bytes2.Count == 0) throw new ArgumentException("Value cannot be an empty collection.", nameof(bytes2));
            if (bytes1.Count != bytes2.Count)
                return null;
            var combineBuffer = new byte[bytes1.Count + bytes2.Count];
            var counter = 0;
            int i = 0, loopTo = combineBuffer.Length - 1;
            for (; i <= loopTo; i += 2)
            {
                if (i >= 0 && combineBuffer.Length > i) combineBuffer[i] = bytes1[counter];
                counter += 1;
            }

            counter = 0;
            var loopTo1 = combineBuffer.Length - 1;
            for (i = 1; i <= loopTo1; i += 2)
            {
                if (i >= 0 && combineBuffer.Length > i) combineBuffer[i] = bytes2[counter];
                counter += 1;
            }

            return combineBuffer;
        }

        public byte[] Concat(byte[] buffer1, byte[] buffer2)
        {
            if (buffer1 == null) throw new ArgumentNullException(nameof(buffer1));
            if (buffer2 == null) throw new ArgumentNullException(nameof(buffer2));
            if (buffer1.Length == 0)
                throw new ArgumentException("Value cannot be an empty collection.", nameof(buffer1));
            if (buffer2.Length == 0)
                throw new ArgumentException("Value cannot be an empty collection.", nameof(buffer2));
            var concatBuffer = new byte[buffer1.Length + buffer2.Length];
            Copy(buffer1, concatBuffer, buffer1.Length);
            Copy(buffer2, 0, concatBuffer, buffer1.Length, buffer2.Length);
            return concatBuffer;
        }

        private static ArrayList Split(IReadOnlyList<byte> byteBuffer)
        {
            if (byteBuffer == null) throw new ArgumentNullException(nameof(byteBuffer));
            if (byteBuffer.Count == 0)
                throw new ArgumentException("Value cannot be an empty collection.", nameof(byteBuffer));
            var splitBuffer1 = new byte[(int)(byteBuffer.Count / 2d - 1d + 1)];
            var splitBuffer2 = new byte[(int)(byteBuffer.Count / 2d - 1d + 1)];
            var returnList = new ArrayList {splitBuffer1, splitBuffer2};
            var counter = 0;
            var i = 0;
            for (var loopTo = splitBuffer1.Length - 1; i <= loopTo; i++)
            {
                if (i >= 0 && splitBuffer1.Length > i) splitBuffer1[i] = byteBuffer[counter];
                counter += 2;
            }

            counter = 1;
            var loopTo1 = splitBuffer2.Length - 1;
            for (i = 0; i <= loopTo1; i++)
            {
                if (i >= 0 && splitBuffer2.Length > i) splitBuffer2[i] = byteBuffer[counter];
                counter += 2;
            }
            return returnList;
        }
    }
}