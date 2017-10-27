import java.io.*;
import java.net.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

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
				//FileInputStream fis = new FileInputStream(clientUploadFile);
				//BufferedInputStream bis = new BufferedInputStream(fis);
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
				FileInputStream fis = new FileInputStream("/home/dell/server_cert.crt");
				CertificateFactory cf = CertificateFactory.getInstance("X509");
				X509Certificate c = (X509Certificate) cf.generateCertificate(fis);
				AuthenticateServer.authServer(c);

			} catch (CertificateException e) {
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