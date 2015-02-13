/// <summary>
/// Demo C# application for: 
/// 	- Private/Public RSA Key Generation. Encryption/Decryption and Signing/Verification for messages using those keys.
///     - X509 Certificate generation.
/// 	- PDF document signing.
/// </summary>
using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace ppkgedsv
{
	class Program
	{
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
			var keys = RSA.Keys (fileName + ".pub", fileName, psw, keySize);
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

			string encryptedMessage = RSA.Encrypt (keys.PublicKey, messageToEncrypt);
			Print (String.Format ("ENCRYPTED MESSAGE:\n{0}", encryptedMessage));

			string decryptedMessage = RSA.Decrypt (keys.PrivateKey, encryptedMessage);
			Print (String.Format ("DECRYPTED MESSAGE:\n{0}", decryptedMessage));

			Print ("======= MESSAGE SIGNING / VERIFICATION =======");
			string messageSignature = RSA.Sign (messageToEncrypt, keys.PrivateKey);
			Print (String.Format("Message: {0}, it's signature: {1}", messageToEncrypt, messageSignature));
			Print (String.Format ("Message: {0}, it's verification status: {1}", messageToEncrypt, RSA.Verify(messageToEncrypt, messageSignature, keys.PublicKey) ? "OK!" : "FAILED"));

			Print ("======= X509 Certificate (self signed) =======");
			Print ("Enter subject name:");
			var subjectName = Console.ReadLine ();

			var caPrivKey = X509.GenerateCACertificate("CN=TEST Root CA");
			var cert = X509.GenerateSelfSignedCertificate(String.Format("CN={0}", subjectName), "CN=TEST Root CA", caPrivKey);

			byte[] certData = cert.Export(X509ContentType.Cert, psw);
			File.WriteAllBytes(String.Format("{0}Certificate.pfx", subjectName), certData);

			Print (String.Format("{0}", cert.ToString()));

			PDFFile.SignPDF (cert, "document.pdf", "document_signed.pdf");

			Print ("all done.");

			Console.WriteLine("<< Hit [any key] to quit. >>");
			Console.ReadKey();
			return;
		}
	}
}