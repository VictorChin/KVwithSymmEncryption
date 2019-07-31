using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp4
{
    class Program
    {
        static void Main(string[] args)
        {

            RijndaelManaged rmCrypto = new RijndaelManaged();

            byte[] keymaterial = new byte[rmCrypto.Key.Length + rmCrypto.IV.Length];
            MemoryStream ms = new MemoryStream(keymaterial);
            ms.Write(rmCrypto.Key);
            ms.Write(rmCrypto.IV);
            var fs = File.OpenWrite(@"C:\test\keymaterial.bin");
            fs.Write(ms.ToArray());
            byte[] wrappedKey = WrapKey(ms);
            fs.Flush();
            fs.Close();
            CryptoStream cryptStream = new CryptoStream(File.OpenWrite(@"C:\test\Encrypted.bin"),
                rmCrypto.CreateEncryptor(), 
                CryptoStreamMode.Write);
            File.OpenRead(@"c:\test\plaintext.txt").CopyTo(cryptStream);
            cryptStream.FlushFinalBlock();
            cryptStream.Close();
            // Begin Decryption
            RijndaelManaged rmCrypto2 = new RijndaelManaged();
            var keystream = File.OpenRead(@"C:\test\keymaterial.bin");
            byte[] key = new byte[rmCrypto2.Key.Length];
            byte[] iv = new byte[rmCrypto2.IV.Length];
            keystream.Read(key, 0, rmCrypto2.Key.Length);
            keystream.Read(iv, 0, rmCrypto2.IV.Length);
            rmCrypto2.Key = key;
            rmCrypto2.IV = iv;
            CryptoStream cryptStream2 = new CryptoStream(File.OpenRead(@"C:\test\Encrypted.bin"),
               rmCrypto2.CreateDecryptor(),
               CryptoStreamMode.Read);
            byte[] plainText = new byte[1024];
            cryptStream2.Read(plainText);
            Console.WriteLine(Encoding.ASCII.GetString(plainText));
            Console.WriteLine("Done");
        }

        private static byte[] WrapKey(MemoryStream ms)
        {

            KeyVaultClient client = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(GetToken));
            Console.WriteLine( $"orginal key+iv:{Convert.ToBase64String(ms.ToArray())}" ); 
            var result = client.WrapKeyAsync("https://vcdemo.vault.azure.net",
                "mykey","", JsonWebKeyEncryptionAlgorithm.RSAOAEP,ms.ToArray()).Result;
            Console.WriteLine($"Wrapped with {result.Kid} -- " + Convert.ToBase64String(result.Result));
            var result2 = client.UnwrapKeyAsync("https://vcdemo.vault.azure.net",
                "mykey", "", JsonWebKeyEncryptionAlgorithm.RSAOAEP, result.Result).Result;
            Console.WriteLine(Convert.ToBase64String(result2.Result));
            return result.Result;
        }

        private static async  Task<string> GetToken(string authority, string resource, string scope)
        {
            var clientID = "C3cbd8c1-6701-4fe6-a1f3-cd7794a53d17";
            var secret = "XVJ0_nBE*kUVTG=/I5RTQ9eBNTnTR7]9";
            ClientCredential credential = new ClientCredential(clientID, secret);
            var context = new AuthenticationContext(authority);
            var result = await context.AcquireTokenAsync(resource, credential);
            return result.AccessToken;

        }
    }
}
