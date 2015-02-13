using System;
using iTextSharp.text.pdf;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using iTextSharp.text.pdf.security;
using System.Security.Cryptography;

namespace ppkgedsv
{
	public class PDFFile
	{
		public static bool SignPDF(X509Certificate2 signature, string sourceDocument, string destinationPath)
		{
			if (signature== null)
				return false;

			PdfReader reader = new PdfReader(sourceDocument);
			using (FileStream fout = new FileStream(destinationPath, FileMode.Create, FileAccess.ReadWrite))
			{
				using (PdfStamper stamper = PdfStamper.CreateSignature(reader, fout, '\0'))
				{
					// digital signature
					var pk=Org.BouncyCastle.Security.DotNetUtilities.GetKeyPair(signature.PrivateKey).Private;
					IExternalSignature es = new PrivateKeySignature(pk, "SHA-256");

					Org.BouncyCastle.X509.X509CertificateParser cp = new Org.BouncyCastle.X509.X509CertificateParser();
					Org.BouncyCastle.X509.X509Certificate[] chain = new[] { cp.ReadCertificate(signature.RawData) };

					try
					{
						MakeSignature.SignDetached(stamper.SignatureAppearance, es, chain, null, null, null, 0, CryptoStandard.CMS);
					}
					catch (CryptographicException ex)
					{
						return false;
					}

					stamper.Close();
				}
			}

			return true;
		}
	}
}

