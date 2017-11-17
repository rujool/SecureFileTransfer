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
		FileTransferProtocol protocol = new FileTransferProtocol();
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
			// Upload file to server
			//protocol.uploadFileToServer(socket,dos, FILENAME);
			
			
			// Download from server
			// protocol.downloadFileFromServer(socket, FILENAME);
			
			// Get certificate from server
			try {
				
				// Download CA certificate from server
				protocol.downloadFileFromServer(socket,dis,"server_cert.crt");
				
				//Verify CA Certificate
				X509Certificate c = protocol.serverVerified();
				PublicKey serverPubKey = c.getPublicKey();
				//System.out.println("Server public key: "+Base64.getEncoder().encode(new String(serverPubKey).getBytes()));
				
				//Generating key spec of the server's private key
				String privateKeyStr = new String(Files.readAllBytes(Paths.get("server_privatekey"))).trim();
 				privateKeyStr = privateKeyStr.replace("-----BEGIN PRIVATE KEY-----\n", "").replace("-----END PRIVATE KEY-----","").trim();
				PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyStr));
				KeyFactory kf = KeyFactory.getInstance("RSA");
				PrivateKey serverPrivateKey = kf.generatePrivate(spec);
				
				//Encrypt the nonce
				//String text = "This is the session key. It is encrypted using server's public key and will be decrypted by the server using its private key!";
				long rand = protocol.generateRandomNonce();
				Cipher ci = Cipher.getInstance("RSA");
				ci.init(Cipher.ENCRYPT_MODE, serverPubKey);
				System.out.println("The random nonce is: " + rand);
				byte[] encrypted = ci.doFinal(protocol.longToBytes(rand));
				//System.err.println(new String(encrypted));
				//System.out.println(new String(encrypted));
				
				dos.writeInt(1);
				dos.flush();
				//Decrypt the nonce
				ci.init(Cipher.DECRYPT_MODE, serverPrivateKey);
				byte[] decrypted = ci.doFinal(encrypted);
				long ldecrypted = protocol.bytesToLong(decrypted);
				//System.err.println(decrypted);
				System.out.println("The decrypted random nonce is: " + ldecrypted);
				dis.close();
				
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