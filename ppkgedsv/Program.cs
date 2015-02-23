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

            Print("======= KEY GENERATION =======");
            Print("Enter filename for your key w/o extention:");
            String fileName = Console.ReadLine();

            int keySize = 1024;

			Print ("Enter password:");
			String psw = Console.ReadLine ();

            Print(String.Format("GENERATING {0} LENGHT KEYS [{1}.pub, {1}]", keySize, fileName));
            var keys = RSA.Keys(fileName + ".pub", fileName, psw, keySize);
            Print(String.Format("PRIVATE KEY: {0}", keys.PrivateKey));
            Print(String.Format("PUBLIC KEY: {0}", keys.PublicKey));

            using (var publicKeyFile = File.CreateText(fileName + ".pub"))
            {
                publicKeyFile.Write(keys.PublicKey);
            }

            using (var privateKeyFile = File.CreateText(fileName))
            {
                privateKeyFile.Write(keys.PrivateKey);
            }

            Print("======= ENCRYPTION / DECRYPTION =======");
            Print("Enter message, to encrypt/decrypt:");
            string messageToEncrypt = Console.ReadLine();

            string encryptedMessage = RSA.Encrypt(keys.PublicKey, messageToEncrypt);
            Print(String.Format("ENCRYPTED MESSAGE:\n{0}", encryptedMessage));

            string decryptedMessage = RSA.Decrypt(keys.PrivateKey, encryptedMessage);
            Print(String.Format("DECRYPTED MESSAGE:\n{0}", decryptedMessage));

            Print("======= MESSAGE SIGNING / VERIFICATION =======");
            string messageSignature = RSA.Sign(messageToEncrypt, keys.PrivateKey);
            Print(String.Format("Message: {0}, it's signature: {1}", messageToEncrypt, messageSignature));
            Print(String.Format("Message: {0}, it's verification status: {1}", messageToEncrypt, RSA.Verify(messageToEncrypt, messageSignature, keys.PublicKey) ? "OK!" : "FAILED"));

			Print ("======= X509 Certificate (self signed) =======");
			Print ("Enter owner name:");
			var ownerName = Console.ReadLine ();
            var city = "Vilnius";
            var countryCode = "LT";

            var caPrivKey = X509.GenerateCACertificate("E=some@email.com, CN=some.domain.com, OU=IT, O=OrganizationX, L=LocationX, ST=LocationX, C=LT");
			var cert = X509.GenerateSelfSignedCertificate(
                String.Format("E={0}@dummymail.{4}, CN={1}, OU=Personal, O={1}, L={2}, ST={2}, C={3}", ownerName.ToLower().Replace(" ", "."), ownerName, city, countryCode, countryCode.ToLower()),
                "E=some@email.com, CN=some.domain.com, OU=IT, O=OrganizationX, L=LocationX, ST=LocationX, C=LT", 
                caPrivKey);

			byte[] certData = cert.Export(X509ContentType.Pfx, psw);
			File.WriteAllBytes(String.Format("{0}_certificate.pfx", ownerName), certData);

			Print (String.Format("{0}", cert.ToString()));

            Print(String.Format("Public Key: {0}", cert.PublicKey.Key.ToXmlString(false)));

            Print(String.Format("Private Key: {0}", cert.PrivateKey.ToXmlString(true)));

            Print("Signing pdf...");

			PDFFile.SignPDF (cert, "document.pdf", "document_signed.pdf");

			Print ("Signing done.");

            Print("Enter message to sign with x509");
            String msg = Console.ReadLine();

            String signed = RSA.Sign(msg, cert.PrivateKey.ToXmlString(true));
            Print("Signed: " + signed);

            Print("Verification status: " + RSA.Verify(msg, signed, cert.PublicKey.Key.ToXmlString(false)));

            String enc = RSA.Encrypt(cert.PublicKey.Key.ToXmlString(false), msg);
            Print("Encrypted with public: " + enc);
            Print("Decrypted with private: " + RSA.Decrypt(cert.PrivateKey.ToXmlString(true), enc));

			Console.WriteLine("<< Done. Hit [any key] to quit. >>");
			Console.ReadKey();
			return;
		}
	}
}