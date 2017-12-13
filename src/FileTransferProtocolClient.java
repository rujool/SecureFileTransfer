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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class FileTransferProtocolClient {
	private PublicKey serverPubKey;
	private long randomNonce, IV;
	private byte[] encryptionKey, integrityKey;
	private long sequenceNumber;
	private static String hashAlgorithm = "HmacSHA256";
	private static final String SERVER_CERT_PATH = "server-certificate.crt";
	
	public long getSequenceNumber() {
		return sequenceNumber;
	}

	public void setSequenceNumber(long sequenceNumber) {
		this.sequenceNumber = sequenceNumber;
	}

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

	public byte[] getIntegrityKey() {
		return integrityKey;
	}

	public void setIntegrityKey(byte[] integrityKey) {
		this.integrityKey = integrityKey;
	}

	public long generateRandomNonce() {
		
		SecureRandom random = new SecureRandom();
		return random.nextLong();
	}
	
	public void uploadFileToServer(Socket socket, DataInputStream dis, DataOutputStream dos, File file) throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
		// Client uploads to server
		long currentSeqNo = Math.abs(generateRandomNonce());
		this.setSequenceNumber(currentSeqNo);
		this.setIV(generateRandomNonce());
		byte[] encryptedIV = this.encrypted(this.getIV(), this.getServerPubKey());
		FileClient.showMessage("Uploading file to server...");
		Mac sha256HMAC = Mac.getInstance(hashAlgorithm);
		SecretKeySpec secretKey = new SecretKeySpec(this.getEncryptionKey(), hashAlgorithm);
		sha256HMAC.init(secretKey);
		
		Mac integrityMac = Mac.getInstance(hashAlgorithm);
		SecretKeySpec integritySecretKey = new SecretKeySpec(this.getIntegrityKey(), hashAlgorithm);
		integrityMac.init(integritySecretKey);
		dos.writeInt(encryptedIV.length);
		dos.write(encryptedIV, 0 , encryptedIV.length);
		FileInputStream fis = new FileInputStream(file.getAbsolutePath());
		BufferedInputStream bis = new BufferedInputStream(fis);
		byte[] fileByte = new byte[1024];
		int bytesRead = bis.read(fileByte, 0 , fileByte.length);
		if(bytesRead > 0) {
			byte[] seqNoBytes = this.longToBytes(currentSeqNo);
			
			byte[] seqNoWithFileData = new byte[bytesRead + seqNoBytes.length];
			System.arraycopy(seqNoBytes, 0, seqNoWithFileData, 0, seqNoBytes.length);
			System.arraycopy(fileByte, 0, seqNoWithFileData, seqNoBytes.length, bytesRead);
			byte[] hmacArr = sha256HMAC.doFinal(encryptedIV);
			byte[] hashLong = new byte[seqNoWithFileData.length];
			for(int i = 0; i < seqNoWithFileData.length; i++) {
				hashLong[i] = hmacArr[i%32];
			}
			
			byte[] xored = xor(seqNoWithFileData, Arrays.copyOfRange(hashLong,0, seqNoWithFileData.length));
			byte[] integrityHmacArr = integrityMac.doFinal(Arrays.copyOfRange(xored, 0, seqNoWithFileData.length));
			
			byte[] xoredWithMac = new byte[xored.length + integrityHmacArr.length];
			System.arraycopy(xored, 0, xoredWithMac, 0, seqNoWithFileData.length);
			System.arraycopy(integrityHmacArr, 0, xoredWithMac, seqNoWithFileData.length, integrityHmacArr.length);
			dos.writeInt(seqNoWithFileData.length + integrityHmacArr.length);
			dos.write(xoredWithMac, 0, seqNoWithFileData.length + integrityHmacArr.length);
			
			
			String goodData = dis.readUTF();
			boolean transferDone = true;
			if(goodData.equals("good")) {
				while(bytesRead != -1) {
					bytesRead = bis.read(fileByte, 0, fileByte.length);
					if(bytesRead > 0) {
						dos.writeUTF("running");
						currentSeqNo = getNextSequenceNumber(xored.length, dos);
						this.setSequenceNumber(currentSeqNo);
						if(currentSeqNo < this.getSequenceNumber()) {
							dos.writeBoolean(true);
							this.keyRollOver(dos);
							secretKey = new SecretKeySpec(this.getEncryptionKey(), hashAlgorithm);
							sha256HMAC.init(secretKey);
							integritySecretKey = new SecretKeySpec(this.getIntegrityKey(), hashAlgorithm);
						}
						else {
							dos.writeBoolean(false);
						}
						encryptionKey = this.getEncryptionKey();
						seqNoBytes = this.longToBytes(currentSeqNo);
						seqNoWithFileData = new byte[bytesRead + seqNoBytes.length];
						System.arraycopy(seqNoBytes, 0, seqNoWithFileData, 0, seqNoBytes.length);
						System.arraycopy(fileByte, 0, seqNoWithFileData, seqNoBytes.length, bytesRead);
						
						hmacArr = sha256HMAC.doFinal(xored);	
						for(int i = 0; i < seqNoWithFileData.length; i++) {
							hashLong[i] = hmacArr[i%32];
						}
						xored = xor(seqNoWithFileData, Arrays.copyOfRange(hashLong, 0 , seqNoWithFileData.length));
						
						integrityHmacArr = integrityMac.doFinal(Arrays.copyOfRange(xored, 0 , seqNoWithFileData.length));
						System.arraycopy(xored, 0, xoredWithMac, 0, seqNoWithFileData.length);
						System.arraycopy(integrityHmacArr, 0, xoredWithMac, seqNoWithFileData.length, integrityHmacArr.length);
						
						dos.writeInt(seqNoWithFileData.length + integrityHmacArr.length);
						dos.write(xoredWithMac, 0 ,seqNoWithFileData.length + integrityHmacArr.length);
						if(!((goodData = dis.readUTF()).equals("good"))){
							FileClient.showMessage("\nError in file transfer!");
							transferDone = false;
							break;
						}
					}
				}
				if(transferDone) {
					FileClient.showMessage("\n File transfer completed successfully");
				}
				dos.writeUTF("close");
				
			}else {
				FileClient.showMessage("\nError in file transfer");
			}
		}
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
		long integrityNonce = this.getIntegrityNonce(this.getRandomNonce());
		this.setIntegrityKey(longToBytes(integrityNonce));
		byte[] encryptedIV = this.encrypted(this.getIV(), this.getServerPubKey());
		dos.writeInt(encryptedIV.length);
		dos.write(encryptedIV, 0, encryptedIV.length);
		
		int encryptedDataLength = dis.readInt();
		File file = new File(fileName);
		FileOutputStream fos = new FileOutputStream(file);
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		
		if(encryptedDataLength > 0) {
			byte[] cipherTextWithMac = new byte[encryptedDataLength];
			dis.read(cipherTextWithMac, 0, encryptedDataLength);
			Mac sha256Hmac = Mac.getInstance(hashAlgorithm);
			SecretKeySpec secretKey = new SecretKeySpec(this.getEncryptionKey(), hashAlgorithm);
			sha256Hmac.init(secretKey);
			
			Mac integrityHmac = Mac.getInstance(hashAlgorithm);
			SecretKeySpec integritySecretKey = new SecretKeySpec(this.getIntegrityKey(),hashAlgorithm);
			integrityHmac.init(integritySecretKey);
			byte[] hashLong = new byte[encryptedDataLength - 32];
			byte[] integrityHmacArr = new byte[32];
			byte[] hashArr = sha256Hmac.doFinal(encryptedIV);
			for(int i = 0; i < hashLong.length; i++) {
				hashLong[i] = hashArr[i%32];
			}
			byte[] cipherText = new byte[cipherTextWithMac.length - 32];
			
			
			System.arraycopy(cipherTextWithMac, 0, cipherText, 0, cipherText.length);
			System.arraycopy(cipherTextWithMac, cipherTextWithMac.length - 32, integrityHmacArr, 0, 32);
			
			
			byte[] encryptedBlock = cipherText;
			byte[] localIntegrityMacArr = integrityHmac.doFinal(cipherText);
			if(!Arrays.equals(localIntegrityMacArr, integrityHmacArr)) {
				dos.writeUTF("reject");
				bos.close();
				fos.close();
				file.delete();
			}
			else {
				dos.writeUTF("good");
			}
			byte[] plainText = xor(cipherText, Arrays.copyOfRange(hashLong, 0 , cipherText.length));
			byte[] seqNo = Arrays.copyOfRange(plainText, 0, 8);
			byte[] plainTextWithoutSeqNo = Arrays.copyOfRange(plainText, 8, plainText.length);
			long seqNoLong = this.bytesToLong(seqNo);
			this.setSequenceNumber(seqNoLong);
			bos.write(plainTextWithoutSeqNo);
			bos.flush();
			String exitStr = null;
			boolean changeKey = false;
			while(true) {
				exitStr = dis.readUTF();
				if(exitStr != null && exitStr.equals("close")) {
					break;
				}
				changeKey = dis.readBoolean();
				if(changeKey) {
					receiveNonceFromServer(dis);
					encryptionKey = this.getEncryptionKey();
					secretKey = new SecretKeySpec(encryptionKey, hashAlgorithm);
					sha256Hmac.init(secretKey);
					integritySecretKey = new SecretKeySpec(this.getIntegrityKey(),hashAlgorithm);
					integrityHmac.init(integritySecretKey);
				}
				if((encryptedDataLength = dis.readInt()) > 0) {
					cipherTextWithMac = new byte[encryptedDataLength];
					dis.read(cipherTextWithMac, 0, encryptedDataLength);
					cipherText = Arrays.copyOfRange(cipherTextWithMac, 0, cipherTextWithMac.length - 32);
					integrityHmacArr = Arrays.copyOfRange(cipherTextWithMac, cipherTextWithMac.length - 32, cipherTextWithMac.length);
					localIntegrityMacArr = integrityHmac.doFinal(cipherText);
					if(!Arrays.equals(localIntegrityMacArr, integrityHmacArr)) {
						dos.writeUTF("reject");
						bos.close();
						fos.close();
						file.delete();
						break;
					}
					hashArr = sha256Hmac.doFinal(encryptedBlock);
					for(int i = 0; i < cipherText.length; i++) {
						hashLong[i] = hashArr[i%32];
					}
					plainText = xor(cipherText, Arrays.copyOfRange(hashLong, 0, cipherText.length));
					seqNo = Arrays.copyOfRange(plainText, 0, 8);
					seqNoLong = this.bytesToLong(seqNo);
					if(!changeKey && seqNoLong - this.getSequenceNumber() != encryptedBlock.length) {
						FileClient.showMessage("Invalid sequence number, rejecting transfer");
						dos.writeUTF("reject");
						bos.close();
						fos.close();
						file.delete();
						break;
					}
					else{
						this.setSequenceNumber(seqNoLong);
						plainTextWithoutSeqNo = Arrays.copyOfRange(plainText, 8, plainText.length);
						bos.write(plainTextWithoutSeqNo, 0, plainTextWithoutSeqNo.length);
						bos.flush();
						encryptedBlock = cipherText;
						dos.writeUTF("good");
					}
				}
				else {
					bos.close();
					fos.close();
					break;
				}
			}
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
	 private long getNextSequenceNumber(int dataLength, DataOutputStream dos) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, IOException {
		long seqNum = (this.getSequenceNumber() + dataLength) % Long.MAX_VALUE;
		return seqNum;
	 }
	 private void sendNonceToServer(long randomNonce, DataOutputStream dos) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, IOException {
		 byte[] encryptedNonce = this.encrypted(randomNonce, this.getServerPubKey());
		 dos.writeInt(encryptedNonce.length);
		 dos.write(encryptedNonce, 0 , encryptedNonce.length);
	 }
	 private void receiveNonceFromServer(DataInputStream dis) throws IOException, NoSuchAlgorithmException {
		 int encryptedNonceLength = dis.readInt();
		 if(encryptedNonceLength > 0) {
			 byte[] encryptedNonce = new byte[encryptedNonceLength];
			 dis.read(encryptedNonce, 0, encryptedNonceLength);
			 byte[] IV = this.longToBytes(this.getIV());
			 byte[] encryptionKey = this.getEncryptionKey();
			 MessageDigest md = MessageDigest.getInstance("SHA1");
			 byte[] concatHash = new byte[IV.length + encryptionKey.length];
			 System.arraycopy(IV, 0, concatHash, 0, IV.length);
			 System.arraycopy(encryptionKey, 0, concatHash, IV.length, encryptionKey.length);
			 byte[] plainText = xor(encryptedNonce, md.digest(concatHash));
			 long decryptedNonce = this.bytesToLong(plainText);
			 this.setRandomNonce(decryptedNonce);
			 this.setEncryptionKey(this.longToBytes(this.getEncryptionNonce(decryptedNonce)));
			 this.setIntegrityKey(this.longToBytes(this.getIntegrityNonce(decryptedNonce)));
		 }
	 }
	 private void keyRollOver(DataOutputStream dos) throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
		 this.setRandomNonce(this.generateRandomNonce());
		 this.setEncryptionKey(this.longToBytes(this.getEncryptionNonce(this.getRandomNonce())));
		 this.setIntegrityKey(this.longToBytes(this.getIntegrityNonce(this.getRandomNonce())));
		 dos.writeBoolean(true);
		 sendNonceToServer(this.getRandomNonce(), dos);
	 }

	public void downloadServerCertificate(Socket clientSocket) throws IOException {
		// TODO Auto-generated method stub
		DataInputStream certDis = new DataInputStream(clientSocket.getInputStream());
		FileOutputStream certFos = new FileOutputStream(SERVER_CERT_PATH);
		DataOutputStream certDos = new DataOutputStream(certFos);
		byte[] fileByte = new byte[64];
		int bytesRead = certDis.readInt();
		while(bytesRead != 0) {
			certDis.read(fileByte, 0, bytesRead);
			if(bytesRead > 0)
			{
				certDos.write(fileByte,0,bytesRead);
			}
			bytesRead = certDis.readInt();
		}
		certDos.close();
	}
}
