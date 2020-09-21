using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace MarkCrypto
{
    public static class MarkCrypto
    {
        public static string Encrypt(string text, string password)
        {
            int keysize = 256;
            int derivationIterations = 100;

            var salt = new byte[32]; // 256 bits
            var iv = new byte[32]; // 256 bits;

            // get random bites for the salt and iv
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(salt);
            rng.GetBytes(iv);
            
            var key = new Rfc2898DeriveBytes(password, salt, derivationIterations).GetBytes(32);
            
            var rijndaelManaged = new RijndaelManaged {
                BlockSize = 256,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };

            var encryptor = rijndaelManaged.CreateEncryptor(key, iv);
            var memoryStream = new MemoryStream();
            var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
            var textBytes = Encoding.UTF8.GetBytes(text);
            cryptoStream.Write(textBytes, 0, textBytes.Length);
            cryptoStream.FlushFinalBlock();
            memoryStream.Close();
            cryptoStream.Close();

            var encryptedText = salt;
            encryptedText = encryptedText.Concat(iv).ToArray();
            encryptedText = encryptedText.Concat(memoryStream.ToArray()).ToArray();
            memoryStream.Close();
            cryptoStream.Close();
            return Convert.ToBase64String(encryptedText);
        }

        public static string Decrypt(string cypherInBase64, string password)
        {
            var encryptedTexPlusSaltAndIVByteArray = Convert.FromBase64String(cypherInBase64);
            var salt = encryptedTexPlusSaltAndIVByteArray.Take(256 / 8).ToArray();
            // Get the IV bytes by extracting the next 32 bytes from the supplied cipherText bytes.
            var iv = encryptedTexPlusSaltAndIVByteArray.Skip(256 / 8).Take(256 / 8).ToArray();
            // Get the actual cipher text bytes by removing the first 64 bytes from the cipherText string.
            var cypherTextBytes = encryptedTexPlusSaltAndIVByteArray.Skip((256 / 8) * 2).Take(encryptedTexPlusSaltAndIVByteArray.Length - ((256 / 8) * 2)).ToArray();

            var rfc = new Rfc2898DeriveBytes(password, salt, 100);//todo this is the iterateions

            var rfcBytes = rfc.GetBytes(256 / 8);

            var rijndaelManaged = new RijndaelManaged 
            {
                BlockSize = 256,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };

            var decryptor = rijndaelManaged.CreateDecryptor(rfcBytes, iv);
            var memStream = new MemoryStream(cypherTextBytes);
            var cryptoStream = new CryptoStream(memStream, decryptor, CryptoStreamMode.Read);
            var plainText = new byte[cypherTextBytes.Length];
            var decryptedByteCount = cryptoStream.Read(plainText, 0, plainText.Length);
            memStream.Close();
            cryptoStream.Close();
            return Encoding.UTF8.GetString(plainText, 0, decryptedByteCount);

        }
    }
}

