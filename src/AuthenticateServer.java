import java.io.FileInputStream;
import java.io.IOException;
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
	public static void authServer(X509Certificate cert) throws Exception{
		try {

			//CA's public key loaded from the file
			String publicKeyStr = new String(Files.readAllBytes(Paths.get("CAPubkey"))).trim();
			publicKeyStr = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtIOcQbyOkWkT/1N4mI7m"
					+ "6wmv7J1yNiakGSr4LOV7WAZpAO0jOPUDQTKn6UEDcYIlaMbIvzKebtFKx59MDNLQ"
					+ "OyNBrm6U38Hlr3jUYsUoP0DqWSRBSdeV5eEpvgioNWr1yEhpxPjHaEvQvgbQ8y1a"
					+ "sUjIGJuRR69W6JcrYnwPvZ6mco8N9qBUw4IoiHiNxUCo5XKhZIJF/69Dm+FkndS4"
					+ "xCo6gQ24U5zSabUIHeWnfGn5OUtYwHnysvUO1RyHdHbbgnCThP/5kF0EV8AffHra"
					+ "c5M6Otyd1bzDB/ldX75VXb8Bq6JraSHsDOsKWgplCEWJcT1xlDRCvfgWGhTU3AOa"
					+ "QwIDAQAB";
			//publicKeyStr = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzGR56LvGNRH5vhtjx9EdRWVNcYQtbvdk6VnyAhChCB1yquDHuoTaF2WxCf2B0DQLdq+OmOwUHr4EHv9zg+C/NJd1jwyNOZf4nE8qTDgIzDVjL9o20JnaJ/kEARjOIJAAEpcMSUrwbBnBwmsdXiGiFKSw7A8kFDCm5OIqe2bPe5GVMRjjn4/l/VWn5AZTRLF2SNzESslsKWnnX0Art9RMHItt/WsXXUAmQWZboZ73zhEST+K6LD1SjRlIOriUP/qyIInNS4VDXFtPDup4+KOZ3Hskh+bCKloGU4PWJzCSuiEOIan2u2lMB+i2pGxIHFRustcZrKA4hFbNYpifFGBQmQIDAQAB";
			
			//getting bytes from the CA's public key string
			//System.out.println(publicKeyStr);
			byte[] data = Base64.getDecoder().decode(publicKeyStr.getBytes());
			
			//Generating key spec of the CA's public key
			X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PublicKey CApublicKey= kf.generatePublic(spec);
			
			//Verifying the certificate by comparing to CA's public key
			cert.verify(CApublicKey);
		}
		catch(Exception e) {
			throw e;
		}
	}
}
