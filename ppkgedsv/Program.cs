/// <summary>
/// Demo C# application for Private/Public RSA Key Generation. Encryption/Decryption and Signing/Verification for messages using those keys.
/// </summary>
using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace ppkgedsv
{
	class Program
	{
		private class KeysCouple {
			public string PrivateKey { get; set; }
			public string PublicKey{ get; set; }

			public KeysCouple(string privateKey, string publicKey) {
				this.PrivateKey = privateKey;
				this.PublicKey = publicKey;
			}
		}

		private static void Print(string text){
			Console.WriteLine (String.Format("\n[{0}] {1}", DateTime.Now.ToString(), text));
		}

		static void Main(string[] args)
		{
			Print("Welcome to Private/Public Key generation, Encryption/Decryption, Signing and Verification demo.");

			Print ("======= KEY GENERATION =======");
			Print ("Enter filename for your key w/o extention:");
			String fileName = Console.ReadLine ();

			int keySize = 1024;

			Print ("Enter password:");
			String psw = Console.ReadLine ();

			Print (String.Format("GENERATING {0} LENGHT KEYS [{1}.pub, {1}]", keySize, fileName));
			var keys = Keys (fileName + ".pub", fileName, psw, keySize);
			Print(String.Format("PRIVATE KEY: {0}", keys.PrivateKey));
			Print(String.Format("PUBLIC KEY: {0}", keys.PublicKey));

			using (var publicKeyFile = File.CreateText(fileName + ".pub")) {
				publicKeyFile.Write(keys.PublicKey);                
			}

			using (var privateKeyFile = File.CreateText(fileName)) {
				privateKeyFile.Write(keys.PrivateKey);      
			}

			Print ("======= ENCRYPTION / DECRYPTION =======");
			Print ("Enter message, to encrypt/decrypt:");
			string messageToEncrypt = Console.ReadLine ();

			string encryptedMessage = Encrypt (keys.PublicKey, messageToEncrypt);
			Print (String.Format ("ENCRYPTED MESSAGE:\n{0}", encryptedMessage));

			string decryptedMessage = Decrypt (keys.PrivateKey, encryptedMessage);
			Print (String.Format ("DECRYPTED MESSAGE:\n{0}", decryptedMessage));

			Print ("======= MESSAGE SIGNING / VERIFICATION =======");
			string messageSignature = Sign (messageToEncrypt, keys.PrivateKey);
			Print (String.Format("Message: {0}, it's signature: {1}", messageToEncrypt, messageSignature));
			Print (String.Format ("Message: {0}, it's verification status: {1}", messageToEncrypt, Verify(messageToEncrypt, messageSignature, keys.PublicKey) ? "OK!" : "FAILED"));

			Console.WriteLine("<< Hit [any key] to quit. >>");
			Console.ReadKey();
			return;

		}

		static KeysCouple Keys(string publicKeyFileName, string privateKeyFileName, string password, int keySize=4096)
		{
			CspParameters cspParams = null;
			string publicKey = "";
			string privateKey = "";

			cspParams = new CspParameters();
			SecureString keyPassword = new SecureString();

			//* PROV_RSA_FULL https://msdn.microsoft.com/en-us/library/system.security.cryptography.cspparameters.providertype(v=vs.110).aspx
			cspParams.ProviderType = 1; 
			cspParams.ProviderName = "";

			//* Convert password into secure string.
			foreach (char c in password) {
				keyPassword.AppendChar(c);
			}

			cspParams.KeyPassword = keyPassword;
			cspParams.Flags = CspProviderFlags.UseArchivableKey;
			cspParams.KeyNumber = (int)KeyNumber.Exchange;

			using (var rsaProvider = new RSACryptoServiceProvider(keySize, cspParams)) {
				try {
					//* Dispose key psw.
					keyPassword.Dispose();

					//* Export public key
					publicKey = rsaProvider.ToXmlString(false);

					//* Export private/public key pair 
					privateKey = rsaProvider.ToXmlString(true);
				} catch (Exception ex) {
					Print (String.Format("[GENERATING KEYS] Exception: {0}", ex.Message));
				}
				finally {
					rsaProvider.PersistKeyInCsp = false;
					rsaProvider.Clear();
				}
			}

			return new KeysCouple (privateKey, publicKey);
		}

		private static string Sign(string message, string privateKey)
		{
			byte[] signedBytes = null;
			CspParameters cspParams = new CspParameters();
			cspParams.ProviderType = 1;
			cspParams.ProviderName = "";

			using (var rsaProvider = new RSACryptoServiceProvider(cspParams))
			{
				byte[] originalData = new UTF8Encoding().GetBytes(message);

				try
				{
					rsaProvider.FromXmlString(privateKey);
					signedBytes = rsaProvider.SignData(originalData, CryptoConfig.MapNameToOID("SHA512"));
				}
				catch (Exception ex)
				{
					Print (String.Format("[SIGN] Exception: {0}", ex.Message));
				}
				finally
				{
					rsaProvider.PersistKeyInCsp = false;
				}
			}

			return Convert.ToBase64String(signedBytes);
		}

		public static bool Verify(string originalMessage, string signedMessage, string publicKey)
		{
			bool success = false;
			CspParameters cspParams = new CspParameters();
			cspParams.ProviderType = 1;
			cspParams.ProviderName = "";

			using (var rsaProvider = new RSACryptoServiceProvider(cspParams))
			{
				byte[] bytesToVerify = new UTF8Encoding().GetBytes(originalMessage);
				byte[] signedBytes = Convert.FromBase64String(signedMessage);
				try
				{
					rsaProvider.FromXmlString(publicKey);
					success = rsaProvider.VerifyData(bytesToVerify, CryptoConfig.MapNameToOID("SHA512"), signedBytes);
				}
				catch (Exception ex)
				{
					Print (String.Format("[VERIFY] Exception: {0}", ex.Message));
				}
				finally
				{
					rsaProvider.PersistKeyInCsp = false;
				}
			}

			return success;
		}

		static string Encrypt(string publicKey, string textToEncrypt)
		{
			byte[] plainBytes = null;
			byte[] encryptedBytes = null;
			string encryptedText = "";

			CspParameters cspParams = new CspParameters();
			cspParams.ProviderType = 1;
			cspParams.ProviderName = "";

			using (var rsaProvider = new RSACryptoServiceProvider(cspParams)) {
				try {
					rsaProvider.FromXmlString(publicKey);

					plainBytes = Encoding.Unicode.GetBytes(textToEncrypt);
					encryptedBytes = rsaProvider.Encrypt(plainBytes, false);
					encryptedText = Convert.ToBase64String(encryptedBytes);
				}
				catch (Exception ex) {
					Print (String.Format("[ENCRYPT] Exception: {0}", ex.Message));
				}
				finally {
					rsaProvider.PersistKeyInCsp = false;
				}
			}

			return encryptedText;
		} 

		static string Decrypt(string privateKey, string encryptedTextBase64)
		{
			CspParameters cspParams = null;
			string decryptedText = "";
			byte[] plainBytes = null;

			cspParams = new CspParameters ();
			cspParams.ProviderType = 1; 
			cspParams.ProviderName = "";
			using (var rsaProvider = new RSACryptoServiceProvider (cspParams)) {
				try {
					rsaProvider.FromXmlString (privateKey);

					plainBytes = rsaProvider.Decrypt (Convert.FromBase64String(encryptedTextBase64), false);
					decryptedText = Encoding.Unicode.GetString (plainBytes);

				} catch (Exception ex) {
					Print (String.Format("[DECRYPT] Exception: {0}", ex.Message));
				} finally {
					rsaProvider.PersistKeyInCsp = false;
				}
			}

			return decryptedText;
		}
	}
}