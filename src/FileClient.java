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

import javax.crypto.Cipher;

public class FileClient{
	
	private static final String HOSTNAME = "127.0.0.1";
	private static final int PORT = 30000;
	private static final String FILENAME = "/home/dell/msg1_client.txt";
	
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
				
				FileOutputStream certFos = new FileOutputStream("/home/dell/server_cert.crt");
				BufferedOutputStream certBos = new BufferedOutputStream(certFos);
				byte[] fileByte = new byte[64];
				int bytesRead = 0;
				while(bytesRead != -1) {
	    			bytesRead = dis.read(fileByte,0,fileByte.length);
	    			if(bytesRead > 0) {
	    				certBos.write(fileByte,0,bytesRead);
	    			}
				}
				certBos.close();
				FileInputStream fisserver = new FileInputStream("/home/dell/CA-certificate.crt");
				CertificateFactory cf = CertificateFactory.getInstance("X509");
				X509Certificate c = (X509Certificate) cf.generateCertificate(fisserver);
				PublicKey serverPubKey = AuthenticateServer.authServer(c);
				//System.out.println("Server public key: "+Base64.getEncoder().encode(new String(serverPubKey).getBytes()));
				// Generate and Encrypt Random Nonce
				long randomNonce = FileTransferProtocol.generateRandomNonce();
				ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
				buffer.putLong(randomNonce);
				Cipher cipher = Cipher.getInstance("RSA");
				cipher.init(Cipher.ENCRYPT_MODE, serverPubKey);
				byte[] encrypted = cipher.doFinal(buffer.array());
				
				// Decryption with private key
				//String privateKeyStr = new String(Files.readAllBytes(Paths.get("/home/dell/server-private.key")));
				String privateKeyStr = new String(Files.readAllBytes(Paths.get("/home/dell/server_privatekey"))).trim();
				privateKeyStr = privateKeyStr.replace("-----BEGIN PRIVATE KEY-----\n", "").replace("-----END PRIVATE KEY-----","").trim();
				System.out.println(privateKeyStr);
				
				/*privateKeyStr = "MIIEpAIBAAKCAQEAzGR56LvGNRH5vhtjx9EdRWVNcYQtbvdk6VnyAhChCB1yquDH"
						+ "uoTaF2WxCf2B0DQLdq+OmOwUHr4EHv9zg+C/NJd1jwyNOZf4nE8qTDgIzDVjL9o2"
						+ "0JnaJ/kEARjOIJAAEpcMSUrwbBnBwmsdXiGiFKSw7A8kFDCm5OIqe2bPe5GVMRjj"
						+ "n4/l/VWn5AZTRLF2SNzESslsKWnnX0Art9RMHItt/WsXXUAmQWZboZ73zhEST+K6"
						+ "LD1SjRlIOriUP/qyIInNS4VDXFtPDup4+KOZ3Hskh+bCKloGU4PWJzCSuiEOIan2"
						+ "u2lMB+i2pGxIHFRustcZrKA4hFbNYpifFGBQmQIDAQABAoIBABUh7ljZ0Ux7Z074"
						+ "lgB65oPeTXuHJwtqGMznt9Xu0jd8k/aG9x+ZzNLOeNeHlnxoZScIT74P6qSjENoD"
						+ "n3XrLtnJLyZzLcbep53BsaXfxUkX3AF+llxLC/tGC9vxLJ7BRMCnTWXmkaUbpKTt"
						+ "XkP1RkTMIl7F0f0kap0PpUTNBHbKD012qqAv8pDia9OLWp+CJWHngiW9euzKs2eE"
						+ "fIHCKfX/AThhypAogrTgqqzB0ohiXJGAHSO5kkVUSpVJCLzNYj01fUQlqbyCZgtU"
						+ "CX5yOADuKNXdOzITLNg/VwWgEP9we7y4kJXfdNfrfL4yP+biisZGwruE9+5/+5YW"
						+ "rOSyoYECgYEA5gN4KL9ckOr/LFrFe8MEx2xoBPBimylL/zExhNq4vdA8y60N+15V"
						+ "HGTN0X52fWkKynLkurBf3TTRDF58wA28jrJYGoZAQ4xlIcaAyDvg6IF2l/HcKTfz"
						+ "tHuyIHLLoH8cOhJvdX8l9ptuflig92UL66385yvtTqBf5+HXKxpW4L0CgYEA43v8"
						+ "TmntG50uaJJZ/0tkkHvbDgpSPR4g7AZ3ri8Q1jnVdtBmq3zWYLRFIytzdhRxY9Ny"
						+ "HFqqwdqacoG58GL5kL6Z4PO0TgLib0H8s10chIEreMnMS5lMq3rfVpzakiLIj9uv"
						+ "RcCk2wnvAwmkGHSyiVXLpse8wd0EHcsFpbgqcw0CgYAhB5CCsXAWc1hvQx2mtwuB"
						+ "o6SQSQCv7U83dxX4UPxEbZm9Wb1vQk2QhT00/yb+vU3KYpNL57XsawA1+X+KiK5y"
						+ "A1Q5gtvJl2iSYBHwLwEOAkFIcne+B4XcfgLHPBTXmEkyYaFVywtljU5hoFKFFCKR"
						+ "FmwBukIaj1cWUkz2qJKfNQKBgQCqzE6VuWZzU0Ki9S9pRPwOl0/TbOBuTw685+Y3"
						+ "+9KSZf3mJXbQzvxOw0sdquQYBiVUpE+LBnAq+Kz5yHkJCecDTHhQs+nuoK/OhSbs"
						+ "rL5apnkzSaCAKmusXKcPatmY21Dm4jTpFEkyxHSWPUjdq9DY2Hf9kv4gOId8rxBg"
						+ "arREiQKBgQDjm8aiSHKaCFYuT5cTsMQwc3MSTLmPnN5W4uAwc4D4LIW66LcSgaXb"
						+ "VQYELCJIl2jgymwV1fmQOCUbOmN0lnw5vuD7a8fDsJyVQRJyZ8kg5Gsn6r5Qx92H"
						+ "JBPUS6d2lnLe/dgiXimCH8KETMNobOcNTEYWxR+JrrAIl8udqfdvmg==";
				*/
				//Generating key spec of the server's private key
				PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyStr));
				KeyFactory kf = KeyFactory.getInstance("RSA");
				PrivateKey serverPrivateKey = kf.generatePrivate(spec);
				
				//Decrypt random nonce
				cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
				byte[] decrypted = cipher.doFinal(encrypted);
				buffer = ByteBuffer.allocate(Long.BYTES);
				buffer.put(decrypted);
				buffer.flip();
				//System.out.println("Decrypted: "+buffer.getLong());
			
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