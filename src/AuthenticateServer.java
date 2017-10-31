import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


public class AuthenticateServer {
	public static void authServer(X509Certificate cert) {
		try {
			
			String keyStr = new String(Files.readAllBytes(Paths.get("/home/dell/ashkan-public.key")));
			System.out.println("KeyStr: "+keyStr);
			System.out.println("keyStr length: " + keyStr.length());
			String publicKeyStr = //"-----BEGIN PUBLIC KEY-----"
					  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtIOcQbyOkWkT/1N4mI7m"
					+ "6wmv7J1yNiakGSr4LOV7WAZpAO0jOPUDQTKn6UEDcYIlaMbIvzKebtFKx59MDNLQ"
					+ "OyNBrm6U38Hlr3jUYsUoP0DqWSRBSdeV5eEpvgioNWr1yEhpxPjHaEvQvgbQ8y1a"
					+ "sUjIGJuRR69W6JcrYnwPvZ6mco8N9qBUw4IoiHiNxUCo5XKhZIJF/69Dm+FkndS4"
					+ "xCo6gQ24U5zSabUIHeWnfGn5OUtYwHnysvUO1RyHdHbbgnCThP/5kF0EV8AffHra"
					+ "c5M6Otyd1bzDB/ldX75VXb8Bq6JraSHsDOsKWgplCEWJcT1xlDRCvfgWGhTU3AOa"
					+ "QwIDAQAB";
								// + "-----END PUBLIC KEY-----"
			System.out.println(publicKeyStr.length());
			KeySpec spec =  new X509EncodedKeySpec(Base64.getDecoder().decode(keyStr));
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PublicKey publicKey = kf.generatePublic(spec);
			
			/*X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyStr));
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PublicKey publicKey = kf.generatePublic(pubKeySpec);*/
		}catch(Exception e) {
			e.printStackTrace();
		}
		/*catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	*/
		
	}
}
