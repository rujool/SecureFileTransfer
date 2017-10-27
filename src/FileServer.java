import java.net.*;
import java.io.*;

public class FileServer {
	private static final int PORT = 30000;
	private static final String FILENAME = "/home/dell/nmap_results.txt";
	private static final String UPLOAD_FILENAME = "/home/dell/upload_server.pdf";
	private static final String SERVER_CERT_PATH = "/home/dell/netsec_materials/CA-certificate.crt";
	
    public static void main(String[] args) throws IOException {
    	ServerSocket socket = new ServerSocket(PORT);
    	Socket clientSocket = socket.accept();
    	try(
    			InputStream is = clientSocket.getInputStream();
    			OutputStream os = clientSocket.getOutputStream();
    			DataInputStream dis = new DataInputStream(clientSocket.getInputStream());
    			FileOutputStream fos = new FileOutputStream(UPLOAD_FILENAME);
    			BufferedOutputStream bos = new BufferedOutputStream(fos);
    			DataOutputStream dos = new DataOutputStream(os);
    			FileInputStream fis = new FileInputStream(FILENAME);
    			BufferedInputStream bis = new BufferedInputStream(fis);
    	   )
    	{
    		// Upload to server
    		/*byte[] fileByte = new byte[64];
    		int bytesRead = 0;
    		while(bytesRead != -1) {
    			bytesRead = dis.read(fileByte,0,fileByte.length);
    			if(bytesRead > 0) {
    				bos.write(fileByte,0,bytesRead);
    			}
    		}*/
    		
    		//Download from server
    		/*byte[] fileByte = new byte[64];
			int bytesRead = 0;
			while(bytesRead != -1) {
				bytesRead = bis.read(fileByte, 0, fileByte.length);
				if(bytesRead > 0)
				{
					dos.write(fileByte,0,bytesRead);
				}
			}*/
			
			// Send certificate to client
			FileInputStream certFis = new FileInputStream(SERVER_CERT_PATH);
			BufferedInputStream certBis = new BufferedInputStream(certFis);
			byte[] fileByte = new byte[64];
			int bytesRead = 0;
			while(bytesRead != -1) {
				bytesRead = certBis.read(fileByte, 0, fileByte.length);
				if(bytesRead > 0)
				{
					dos.write(fileByte,0,bytesRead);
				}
			}
			certBis.close();
			
    	}catch(IOException e) {
    		e.printStackTrace();
    	}
    	finally {
    		socket.close();
    	}
    }
}
