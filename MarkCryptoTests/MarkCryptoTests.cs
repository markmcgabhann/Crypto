using Microsoft.VisualStudio.TestTools.UnitTesting;
using MarkCrypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MarkCrypto.Tests
{
    [TestClass()]
    public class MarkCryptoTests
    {
        [TestMethod()]
        public void CanEncryptStringAndDecryptItBack()
        {
            //Arrange
            var plainText = "test string";
            var password = "abcd1234";

            //Act
            var encryptedText = MarkCrypto.Encrypt(plainText, password);
            var unecryptedText = MarkCrypto.Decrypt(encryptedText, password);

            //Assert
            Assert.AreEqual(plainText, unecryptedText);
        }
    }
}