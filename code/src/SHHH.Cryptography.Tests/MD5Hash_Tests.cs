// <copyright file="MD5Hash_Tests.cs" company="SHHH Innovations LLC">
// Copyright SHHH Innovations LLC
// </copyright>

namespace SHHH.Cryptography.Tests
{
    using NUnit.Framework;

    /// <summary>
    /// The MD5 hash test fixture
    /// </summary>
    [TestFixture]
    public class MD5Hash_Tests
    {
        /// <summary>
        /// Tests calculating the hash.
        /// </summary>
        [Test]
        public void CalculateHash_Test()
        {
            var result = MD5Hash.ComputeHash("geoff@shhhinnovations.com");

            Assert.AreEqual("fa49706cc48a26575b42cd787abc11b9", result);
        }
    }
}
