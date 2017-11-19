import java.nio.ByteBuffer;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class FileTransferProtocolClient {
	private static DataOutputStream dos;
	
	public long generateRandomNonce() {
		
		SecureRandom random = new SecureRandom();
		return random.nextLong();
	}
	
	public void uploadFileToServer(ServerSocket socket, DataOutputStream dos, String fileName) throws IOException {
		// Client uploads to server
		FileInputStream fis = new FileInputStream(fileName);
		BufferedInputStream bis = new BufferedInputStream(fis);
		
		
		byte[] fileByte = new byte[64];
		int bytesRead = 0;
		while(bytesRead != -1) {
			bytesRead = bis.read(fileByte, 0, fileByte.length);
			if(bytesRead > 0)
			{
				dos.write(fileByte,0,bytesRead);
			}
		}
		FileClient.showMessage("\nFile has been uploaded succesfully to the server!\n");
		bis.close();
		fis.close();
		dos.flush();
		//dos.close();
	}
	
	public void downloadFileFromServer(Socket socket, DataInputStream dis, String fileName) throws IOException {
		// Client downloads file from server
		FileOutputStream fos = new FileOutputStream(fileName);
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		byte[] fileByte = new byte[64];
		int bytesRead = 0;
		while(bytesRead != -1) {
			bytesRead = dis.read(fileByte,0,fileByte.length);
			if(bytesRead > 0) {
				bos.write(fileByte,0,bytesRead);
			}
		}
		FileClient.showMessage("\nFile has been downloaded succesfully from the server!\n");
		bos.close();
		fos.close();
	}
	
	public X509Certificate serverVerified(String filename) throws Exception{
					
		FileInputStream fisserver = new FileInputStream(filename);
		CertificateFactory cf = CertificateFactory.getInstance("X509");
		X509Certificate cert = (X509Certificate) cf.generateCertificate(fisserver);
		//System.out.println(cert.toString());
		//CA's public key loaded from the file
		String publicKeyStr = new String(Files.readAllBytes(Paths.get("CAPubkey"))).trim();
		/*publicKeyStr = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtIOcQbyOkWkT/1N4mI7m"
				+ "6wmv7J1yNiakGSr4LOV7WAZpAO0jOPUDQTKn6UEDcYIlaMbIvzKebtFKx59MDNLQ"
				+ "OyNBrm6U38Hlr3jUYsUoP0DqWSRBSdeV5eEpvgioNWr1yEhpxPjHaEvQvgbQ8y1a"
				+ "sUjIGJuRR69W6JcrYnwPvZ6mco8N9qBUw4IoiHiNxUCo5XKhZIJF/69Dm+FkndS4"
				+ "xCo6gQ24U5zSabUIHeWnfGn5OUtYwHnysvUO1RyHdHbbgnCThP/5kF0EV8AffHra"
				+ "c5M6Otyd1bzDB/ldX75VXb8Bq6JraSHsDOsKWgplCEWJcT1xlDRCvfgWGhTU3AOa"
				+ "QwIDAQAB";
		*/
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
		return cert;
	}
	
	
	public byte[] encrypted(PublicKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException  {
		//Encrypt the nonce
				//String text = "This is the session key. It is encrypted using server's public key and will be decrypted by the server using its private key!";
				long rand = generateRandomNonce();
				Cipher ci = Cipher.getInstance("RSA");
				ci.init(Cipher.ENCRYPT_MODE, key);
				FileClient.showMessage("\nThe randomly generated nonce is: " + rand+"\n");
				byte[] encrypted = ci.doFinal(longToBytes(rand));
				//System.err.println(new String(encrypted));
				//System.out.println(new String(encrypted));
				//dos.writeInt(1);
				//dos.flush();
				return encrypted;				
		}
	
	public byte[] longToBytes(long x) {
	    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
	    buffer.putLong(x);
	    return buffer.array();
	}
	
	public long bytesToLong(byte[] bytes) {
	    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
	    buffer.put(bytes);
	    buffer.flip();//need flip 
	    return buffer.getLong();
	}
}
