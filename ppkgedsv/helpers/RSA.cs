using System;
using System.Security.Cryptography;
using System.Security;
using System.Text;

namespace ppkgedsv
{
	public class RSA
	{
		private static void Print(string text){
			Console.WriteLine (String.Format("\n[{0}] {1}", DateTime.Now.ToString(), text));
		}

		public class KeysCouple {
			public string PrivateKey { get; set; }
			public string PublicKey{ get; set; }

			public KeysCouple(string privateKey, string publicKey) {
				this.PrivateKey = privateKey;
				this.PublicKey = publicKey;
			}
		}

		public static KeysCouple Keys(string publicKeyFileName, string privateKeyFileName, string password, int keySize=4096)
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

		public static string Sign(string message, string privateKey)
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

		public static string Encrypt(string publicKey, string textToEncrypt)
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

		public static string Decrypt(string privateKey, string encryptedTextBase64)
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

