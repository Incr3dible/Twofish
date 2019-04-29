using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Twofish.Tests
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.Title = "Twofish.Tests";

            var bIn = Encoding.UTF8.GetBytes("It works!");
            byte[] key = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}; // 128bit key
            byte[] iv = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}; // initialization vector 

            using (var algorithm = new TwofishManaged {KeySize = key.Length * 8, Mode = CipherMode.CBC})
            {
                byte[] encrypted;

                using (var ms = new MemoryStream())
                {
                    using (var transform = algorithm.CreateEncryptor(key, iv))
                    {
                        using (var cs = new CryptoStream(ms, transform, CryptoStreamMode.Write))
                        {
                            cs.Write(bIn, 0, bIn.Length);
                        }
                    }

                    encrypted = ms.ToArray();

                    Console.WriteLine($"Encrypted: {BitConverter.ToString(encrypted).Replace("-", string.Empty)}");
                }

                using (var ms = new MemoryStream())
                {
                    using (var transform = algorithm.CreateDecryptor(key, iv))
                    {
                        using (var cs = new CryptoStream(ms, transform, CryptoStreamMode.Write))
                        {
                            cs.Write(encrypted, 0, encrypted.Length);
                        }
                    }

                    Console.WriteLine($"Decrypted: {Encoding.UTF8.GetString(ms.ToArray())}");
                }
            }

            Console.Read();
        }
    }
}