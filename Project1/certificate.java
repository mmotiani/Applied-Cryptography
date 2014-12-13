import java.io.FileInputStream;
import java.security.*;
import java.security.PublicKey;
import java.security.Principal;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyFactory;
import java.math.BigInteger;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.io.IOException;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;

public class certificate{

	public static void main(String args[]){

		ClassLoader cl = Thread.currentThread().getContextClassLoader();
		String pt = cl.getResource(".").getPath();		// setting path to get the cerificate from the specified location
		String ragpubc = pt+"Raghupub.cer";
		String ragpvtc = pt+"Raghupri.pfx";
		String cacerti = pt+"Trustcenter.cer";

		try{
		
		/* Printing Raghu's Certificate */
		
			System.out.println();
			System.out.println();			
			System.out.println("***************************************************************************");		
			System.out.println("Raghu's Certificate");
			System.out.println("***************************************************************************");
			System.out.println();
			System.out.println();
			System.out.println();
			FileInputStream fis = new FileInputStream(ragpubc);
			CertificateFactory cerf = CertificateFactory.getInstance("X509");
			X509Certificate xcert = (X509Certificate)cerf.generateCertificate(fis);						
			fis.close();
			System.out.println(xcert);		//Printing certificate
			System.out.println();
			System.out.println();
			System.out.println();
			System.out.println();
			System.out.println();
		
		/*Printing Raghu's Public Key */
			
			System.out.println("***************************************************************************");		
			System.out.println("Raghu's Public Key");
			System.out.println("***************************************************************************");
			System.out.println();
			System.out.println();
			System.out.println();
			FileInputStream fis1 = new FileInputStream(ragpubc);
			CertificateFactory cerf1 = CertificateFactory.getInstance("X509");
			X509Certificate xcert1 = (X509Certificate)cerf1.generateCertificate(fis1);						
			fis1.close();
			System.out.println(xcert1.getPublicKey());	//Printing public key
			System.out.println();
			System.out.println();
			System.out.println();
			System.out.println();
			System.out.println();
		
		/*Printing Raghu's Private Key */
		
			String str = "raghu";
			System.out.println("***************************************************************************");		
			System.out.println("Raghu's Private Key");
			System.out.println("***************************************************************************");
			System.out.println();
			System.out.println();
			System.out.println();
			FileInputStream fis2 = new FileInputStream(ragpvtc);
			KeyStore keyst = KeyStore.getInstance("PKCS12", "SunJSSE");
			char[] c = str.toCharArray();
			keyst.load(fis2,c);
			fis2.close();
			PasswordProtection pp=new PasswordProtection(c);
			String s = keyst.aliases().nextElement();			
			KeyStore.PrivateKeyEntry pvtkeyent = (KeyStore.PrivateKeyEntry)keyst.getEntry(s, pp);
			PrivateKey pvtkey = pvtkeyent.getPrivateKey();
			System.out.println(pvtkey);			//Printing ptivate key
			System.out.println();
			System.out.println();
			System.out.println();
			System.out.println();
			System.out.println();

		/*Printing public key of certification authority */
			
			System.out.println("***************************************************************************");		
			System.out.println("Public Key of Certification Authority");
			System.out.println("***************************************************************************");
			System.out.println();
			System.out.println();
			System.out.println();
			FileInputStream fis3 = new FileInputStream(cacerti);
			CertificateFactory cerf2 = CertificateFactory.getInstance("X509");
			X509Certificate xcert2 = (X509Certificate)cerf2.generateCertificate(fis3);						
			fis1.close();
			System.out.println(xcert2.getPublicKey());		//Printing public key of CA
			System.out.println();
			System.out.println();
			System.out.println();
			System.out.println();
			System.out.println();
			
		/*Printing Signature of TA's Certificate*/

			System.out.println("***************************************************************************");		
			System.out.println("Signature on TA's certificate");
			System.out.println("***************************************************************************");
			System.out.println();
			System.out.println();
			System.out.println();
			byte[] by = xcert.getSignature();
			String st= new BigInteger(by).toString(16);
			System.out.println(st);			//Printing TA's signature
			System.out.println();
			System.out.println();
			System.out.println();
			System.out.println();
			System.out.println();
			
		/*Verification of Raghu's certificate*/

			System.out.println("***************************************************************************");		
			System.out.println("Verify raghu's certificate");
			System.out.println("***************************************************************************");
			System.out.println();
			System.out.println();
			xcert.verify(xcert2.getPublicKey());		//verifying certificate
			System.out.println("Raghu's Certificate is Verified");
			System.out.println();
			System.out.println();
			System.out.println();
			System.out.println();
			System.out.println();

		/*Encryption and Decryption of the string using RSA */
			
			System.out.println("***************************************************************************");		
			System.out.println("Encryption & Decryption of the string using RSA");
			System.out.println("***************************************************************************");
			System.out.println();
			System.out.println();
			System.out.println();
			System.out.println();
			System.out.println();
			String string = "Our names are Mohit Motiani and Basavaprasad Chandu. We are enrolled in CSE539";
			
			System.out.println("PLAIN TEXT: "+string); //Printing plain text
			System.out.println();
			System.out.println();
			
			System.out.println("ENCRYPTION USING RSA");  //Encryption Using RSA
			System.out.println("____________________");
			System.out.println();
			Cipher rsaenc;
			rsaenc=Cipher.getInstance("RSA");
			rsaenc.init(Cipher.ENCRYPT_MODE, xcert1.getPublicKey()); 	//encrypting using public key of raghu
			byte[] by1=rsaenc.doFinal(string.getBytes());	
			String str2 = new BigInteger(by1).toString(16);
			System.out.println(str2);
			
			System.out.println();
			System.out.println();
			System.out.println("DECRYPTION USING RSA");   //Decryption Using RSA
			System.out.println("____________________");
			System.out.println();
			Cipher rsadec;
			rsadec = Cipher.getInstance("RSA");
			rsadec.init(Cipher.DECRYPT_MODE, pvtkey);		//decrypting using private key of raghu
			byte[] by3 = rsadec.doFinal(by1);
			String str3 = new String(by3,"UTF8");
			System.out.println(str3);
			
			
		}
		catch(Exception e){
			System.out.println("Error Mesaage"+e.getMessage());
		}
	}
}
