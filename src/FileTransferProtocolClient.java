import java.nio.ByteBuffer;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
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
	private PublicKey serverPubKey;
	private long randomNonce, IV;
	private byte[] encryptionKey, integrityKey;
	
	public PublicKey getServerPubKey() {
		return serverPubKey;
	}

	public void setServerPubKey(PublicKey serverPubKey) {
		this.serverPubKey = serverPubKey;
	}

	public long getRandomNonce() {
		return randomNonce;
	}

	public void setRandomNonce(long randomNonce) {
		this.randomNonce = randomNonce;
	}

	public long getIV() {
		return IV;
	}

	public void setIV(long iV) {
		IV = iV;
	}
	
	public byte[] getEncryptionKey() {
		return encryptionKey;
	}

	public void setEncryptionKey(byte[] encryptionKey) {
		this.encryptionKey = encryptionKey;
	}

	public long generateRandomNonce() {
		
		SecureRandom random = new SecureRandom();
		return random.nextLong();
	}
	
	public void uploadFileToServer(ServerSocket socket, DataOutputStream dos, File file) throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
		// Client uploads to server
		
		this.setIV(generateRandomNonce());
		FileClient.showMessage("At client, IV: "+this.getIV());
		byte[] encryptedIV = this.encrypted(this.getIV(), this.getServerPubKey());
		
		dos.writeInt(encryptedIV.length);
		dos.write(encryptedIV, 0 , encryptedIV.length);
		FileInputStream fis = new FileInputStream(file.getAbsolutePath());
		BufferedInputStream bis = new BufferedInputStream(fis);
		byte[] encryptionKey = this.getEncryptionKey();
		byte[] IVdataBlock = new byte[encryptedIV.length + encryptionKey.length];
		System.arraycopy(encryptedIV, 0, IVdataBlock, 0, encryptedIV.length);
		System.arraycopy(encryptionKey, 0, IVdataBlock, encryptedIV.length, encryptionKey.length);
		MessageDigest md = MessageDigest.getInstance("SHA1");
		byte[] sha1Hash = md.digest(IVdataBlock);
		byte[] fileByte = new byte[20];
		int bytesRead = bis.read(fileByte, 0 , fileByte.length);
		byte[] xored = xor(fileByte, sha1Hash);
		dos.writeInt(xored.length);
		dos.write(xored, 0, xored.length);
		
		while(bytesRead != -1) {
			bytesRead = bis.read(fileByte, 0, bytesRead);
			if(bytesRead > 0) {
				byte[] hashedBlock = new byte[xored.length + encryptionKey.length];
				System.arraycopy(xored, 0, hashedBlock, 0, xored.length);
				System.arraycopy(encryptionKey, 0, hashedBlock, xored.length, encryptionKey.length);
				byte[] hashValue = md.digest(hashedBlock);
				byte[] cipherText = xor(fileByte, hashValue);
				dos.writeInt(bytesRead);
				dos.write(cipherText, 0 , bytesRead);
			}
		}
			
		FileClient.showMessage("\nFile has been uploaded successfully to the server!\n");
		bis.close();
		fis.close();
	}
	
	public void downloadFileFromServer(Socket socket, DataInputStream dis, DataOutputStream dos, String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

		byte[] encryptedRandomNonce = this.encrypted(this.getRandomNonce(), this.getServerPubKey());
		dos.writeInt(encryptedRandomNonce.length);
		dos.write(encryptedRandomNonce, 0, encryptedRandomNonce.length);
		this.setIV(generateRandomNonce());
		long encryptionNonce = this.getEncryptionNonce(this.getRandomNonce());
		this.setEncryptionKey(longToBytes(encryptionNonce));
		System.out.println("At client, encryption key: "+new String(this.getEncryptionKey()));
		byte[] encryptedIV = this.encrypted(this.getIV(), this.getServerPubKey());
		dos.writeInt(encryptedIV.length);
		dos.write(encryptedIV, 0, encryptedIV.length);
		FileOutputStream fos = new FileOutputStream(fileName);
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		int encryptedDataLength = dis.readInt();
		if(encryptedDataLength > 0) {
			byte[] encryptedBlock = new byte[encryptedDataLength];
			dis.read(encryptedBlock, 0, encryptedDataLength);
			MessageDigest md = MessageDigest.getInstance("SHA1");
			byte[] concatEncrypted = new byte[encryptionKey.length + encryptedIV.length];
			System.arraycopy(encryptedIV, 0, concatEncrypted, 0, encryptedIV.length);
			System.arraycopy(encryptionKey, 0, concatEncrypted, encryptedIV.length, encryptionKey.length);
			byte[] sha1HashConcat = md.digest(concatEncrypted);
			byte[] plainText = xor(encryptedBlock, sha1HashConcat);
			System.out.println("At client, plaintext: "+new String(plainText));
			bos.write(plainText);
			bos.flush();
			
			while((encryptedDataLength = dis.readInt()) > 0) {
				byte[] cipherText = new byte[encryptedDataLength];
				dis.read(cipherText, 0, encryptedDataLength);
				concatEncrypted = new byte[encryptedBlock.length + encryptionKey.length];
				System.arraycopy(encryptedBlock, 0, concatEncrypted, 0, encryptedBlock.length);
				System.arraycopy(encryptionKey, 0, concatEncrypted, encryptedBlock.length, encryptionKey.length);
				sha1HashConcat = md.digest(concatEncrypted);
				plainText = xor(cipherText, sha1HashConcat);
				bos.write(plainText, 0, encryptedDataLength);
				bos.flush();
			}
			bos.close();
			fos.close();
		}
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
	
	
	public byte[] encrypted(long rand, PublicKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException  {
		//Encrypt the nonce
				//String text = "This is the session key. It is encrypted using server's public key and will be decrypted by the server using its private key!";
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
	
	public long getEncryptionNonce(long sessionKey) {
		if(sessionKey > 0) {
			return sessionKey - 1;
		}
		return sessionKey + 1;
	}
	public long getIntegrityNonce(long sessionKey) {
		if(sessionKey > 0) {
			return sessionKey - 2;
		}
		return sessionKey + 2;
	}
	
	 public static byte[] xor(byte[] data1, byte[] data2) {
	        // make data2 the largest...
		 byte[] data1Local = data1.clone(), data2Local = data2.clone();
	        if (data1Local.length > data2Local.length) {
	            byte[] tmp = data2Local;
	            data2Local = data1Local;
	            data1Local = tmp;
	        }
	        for (int i = 0; i < data1Local.length; i++) {
	            data2Local[i] ^= data1Local[i];
	        }
	        return data2Local;
	    }
}
