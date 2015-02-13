//using System;
//using iTextSharp.text.pdf;
//using System.Security.Cryptography.X509Certificates;
//using System.IO;
//using iTextSharp.text.pdf.security;
//using System.Security.Cryptography;
//
//namespace ppkgedsv
//{
//	public class PDFFile
//	{
//		public static string SignPDF(X509Certificate2 signature, string sourceDocument, string destinationPath)
//		{
//
//			if (signature== null)
//			{
//				return "Invalid signature.";
//			}
//
//			PdfReader reader = new PdfReader(sourceDocument);
//			using (FileStream fout = new FileStream(destinationPath, FileMode.Create, FileAccess.ReadWrite))
//			{
//				using (PdfStamper stamper = PdfStamper.CreateSignature(reader, fout, '\0'))
//				{
//					// appearance
//					PdfSignatureAppearance appearance = stamper.SignatureAppearance;
//
//					appearance.Image = new iTextSharp.text.pdf.PdfImage();
//					appearance.Reason = "";
//					appearance.Location = "";
//					appearance.SetVisibleSignature(new iTextSharp.text.Rectangle(20, 10, 170, 60), 1, "Icsi-Vendor");
//
//					// digital signature
//					var pk=Org.BouncyCastle.Security.DotNetUtilities.GetKeyPair(signature.PrivateKey).Private;
//					IExternalSignature es = new PrivateKeySignature(pk, "SHA-256");
//
//					Org.BouncyCastle.X509.X509CertificateParser cp = new Org.BouncyCastle.X509.X509CertificateParser();
//
//					Org.BouncyCastle.X509.X509Certificate[] chain = new[] { cp.ReadCertificate(signature.RawData) };
//
//					try
//					{
//						MakeSignature.SignDetached(appearance, es, chain, null, null, null, 0, CryptoStandard.CMS);
//					}
//
//					catch (CryptographicException ex)
//
//					{
//
//						switch (ex.Message)
//
//						{
//
//						case "Action aborted by user.\r\n":
//
//							return ex.Message;
//
//						case "Key not found.\r\n":
//
//							return "Signature not found in your computer.";
//
//						}
//
//						throw;
//
//					}
//
//					stamper.Close();
//
//					return "Correct";
//
//				}
//
//			}
//
//		}
//	}
//}
//
