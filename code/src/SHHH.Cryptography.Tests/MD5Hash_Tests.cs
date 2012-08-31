using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;

namespace SHHH.Cryptography.Tests
{
    [TestFixture]
    public class MD5Hash_Tests
    {
        [Test]
        public void CalculateHash_Test()
        {
            var result = MD5Hash.ComputeHash("geoff@shhhinnovations.com");

            Assert.AreEqual("fa49706cc48a26575b42cd787abc11b9", result);
        }
    }
}
