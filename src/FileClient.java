import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Cipher;

public class FileClient{
	
	private static final String HOSTNAME = "127.0.0.1";
	private static final int PORT = 30000;
	private static final String FILENAME = "test.txt";
	
	public static void main(String [] args) {
		
		File clientDownloadFile = new File(FILENAME);
		/*if(args.length == 0) {
			System.out.println(" Usage: java FileClient <-u | -d> <filename>"
							+ " \n -u: Upload file"
							+ " \n -d: Download file"
							+ " \n filename: Name of file to be uploaded/downloaded");
			return;
		}
		String fileOption = args[0];
		if(fileOption.toLowerCase().equals("-u")) {
			System.out.println("Upload file");
			return;
		}
		*/
		try(
				Socket socket = new Socket(HOSTNAME,PORT);
				OutputStream os = socket.getOutputStream();
				InputStream is = socket.getInputStream();
				DataOutputStream dos = new DataOutputStream(os);
				FileInputStream fis = new FileInputStream(clientDownloadFile);
				BufferedInputStream bis = new BufferedInputStream(fis);
				DataInputStream dis = new DataInputStream(is);
				FileOutputStream fos = new FileOutputStream(clientDownloadFile);
				BufferedOutputStream bos = new BufferedOutputStream(fos);
		   )
		{
			// Client uploads to server
			/*byte[] fileByte = new byte[64];
			int bytesRead = 0;
			while(bytesRead != -1) {
				bytesRead = bis.read(fileByte, 0, fileByte.length);
				if(bytesRead > 0)
				{
					dos.write(fileByte,0,bytesRead);
				}
			}*/
			// Download from server
			/*byte[] fileByte = new byte[64];
			int bytesRead = 0;
			while(bytesRead != -1) {
    			bytesRead = dis.read(fileByte,0,fileByte.length);
    			if(bytesRead > 0) {
    				bos.write(fileByte,0,bytesRead);
    			}
			}*/
			
			// Get certificate from server
			try {
				
			/*	FileOutputStream certFos = new FileOutputStream("CA-certificate.crt");
				BufferedOutputStream certBos = new BufferedOutputStream(certFos);
				byte[] fileByte = new byte[64];
				int bytesRead = 0;
				while(bytesRead != -1) {
	    			bytesRead = dis.read(fileByte,0,fileByte.length);
	    			if(bytesRead > 0) {
	    				certBos.write(fileByte,0,bytesRead);
	    			}
				}
				certBos.close();*/
				FileInputStream fisserver = new FileInputStream("server-certificate.crt");
				CertificateFactory cf = CertificateFactory.getInstance("X509");
				X509Certificate c = (X509Certificate) cf.generateCertificate(fisserver);
				AuthenticateServer.authServer(c);
				PublicKey serverPubKey = c.getPublicKey();
				
				// Getting private key
				//String privateKeyStr = new String(Files.readAllBytes(Paths.get("/home/dell/server-private.key")));
				String privateKeyStr = new String(Files.readAllBytes(Paths.get("server_privatekey"))).trim();
				privateKeyStr = privateKeyStr.replace("-----BEGIN PRIVATE KEY-----\n", "").replace("-----END PRIVATE KEY-----","").trim();
				//System.out.println("Private Key:" + privateKeyStr);
				
				//Generating key spec of the server's private key
				PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyStr));
				KeyFactory kf = KeyFactory.getInstance("RSA");
				PrivateKey serverPrivateKey = kf.generatePrivate(spec);
				
				//Encrypt the nonce
				//String text = "This is the session key. It is encrypted using server's public key and will be decrypted by the server using its private key!";
				long rand = FileTransferProtocol.generateRandomNonce();
				Cipher ci = Cipher.getInstance("RSA");
				ci.init(Cipher.ENCRYPT_MODE, serverPubKey);
				System.out.println("The random nonce is: " + rand);
				byte[] encrypted = ci.doFinal(FileTransferProtocol.longToBytes(rand));
				//System.err.println(new String(encrypted));
				//System.out.println(new String(encrypted));
				
				//Decrypt the nonce
				ci.init(Cipher.DECRYPT_MODE, serverPrivateKey);
				String decrypted = new String(ci.doFinal(encrypted));
				long ldecrypted = FileTransferProtocol.bytesToLong(decrypted.getBytes());
				//System.err.println(decrypted);
				System.out.println("The decrypted random nonce is: " + ldecrypted);
				
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
				
			} catch (UnknownHostException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
	}
	
}