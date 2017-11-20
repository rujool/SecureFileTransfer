import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

public class FileClient extends JFrame {

	//File clientDownloadFile = new File(FILENAME);
	String uploadFileName;
	String downloadFileName;
	FileTransferProtocolClient protocol = new FileTransferProtocolClient();
	//private static final String FILENAME = "test.txt";
	private static final int PORT = 6689;
	private static final String SERVER_CERT_PATH = "server-certificate.crt";
	private static final long serialVersionUID = 1L;
	//private JTextField userText;
	private static JButton Upload;
	private static JButton Download;
	private static JTextArea Window;
	private static JPanel Panel;
	//private ObjectOutputStream output;
	//private ObjectInputStream input;
	private static ServerSocket socket;
	private static Socket clientSocket;
	private static InputStream is;
	private static OutputStream os;
	private static DataInputStream dis;
	private static FileOutputStream fos;
	private static BufferedOutputStream bos;
	private static DataOutputStream dos;
	private static FileInputStream fis;
	private static BufferedInputStream bis;
	//private String message = "";
	private String ServerIP;
	private static final JFileChooser fc = new JFileChooser();

	//constructor
	public FileClient(String host){
		setTitle("CLIENT - FTP");
		ServerIP = host;
		//userText = new JTextField();							
		Window = new JTextArea();													
		Upload = new JButton("Upload");						
		Download = new JButton("Download");
		Panel = new JPanel();									// The main panel that consists of all of the above
		JScrollPane scrollPane = new JScrollPane(Window);	 // Scroll panel for the window
		this.setSize(600, 500);									// setting the size of the whole window
		this.setVisible(true);									// setting its visibility as true
		Panel.setLayout(null);									//setting layout as null
		this.add(Panel);										// adding panel to out window
		scrollPane.setBounds(10, 10, 550, 400);					// setting bounds for the scroll panel that is attched to the window
		Panel.add(scrollPane);									//adding scrollPane to the panel
		//userText.setBounds(10, 420, 280, 30);					// setting bounds for the input text area
		//Panel.add(userText);									// adding input area to the panel
		Upload.setBounds(175, 420, 100, 30);						// setting bounds for the button
		Panel.add(Upload);										// adding button to the panel
		Download.setBounds(300, 420, 100, 30);						// setting bounds for the button
		Panel.add(Download);										// adding button to the panel
		Window.setBackground(Color.LIGHT_GRAY);
		Window.setForeground(Color.BLUE );
		Window.setBorder(BorderFactory.createLineBorder(Color.black));
		Window.setEditable(false);							
		Upload.addActionListener(
				new ActionListener(){
					public void actionPerformed(ActionEvent e){
						//Handle button action
						if (e.getSource() == Upload) {
							int returnVal = fc.showOpenDialog(Window);
							if (returnVal == JFileChooser.APPROVE_OPTION) {
								File file = fc.getSelectedFile();
								//selected file name
								uploadFileName = file.getName();
								//System.out.println(uploadFileName);
								try {
									//send file name to server
									dos.writeUTF(uploadFileName);
									protocol.uploadFileToServer(socket, dos, file);
									
								} catch (IOException ioe){
									ioe.getStackTrace();
								} catch (InvalidKeyException e1) {
									// TODO Auto-generated catch block
									e1.printStackTrace();
								} catch (NoSuchPaddingException e1) {
									// TODO Auto-generated catch block
									e1.printStackTrace();
								} catch (NoSuchAlgorithmException e1) {
									// TODO Auto-generated catch block
									e1.printStackTrace();
								} catch (BadPaddingException e1) {
									// TODO Auto-generated catch block
									e1.printStackTrace();
								} catch (IllegalBlockSizeException e1) {
									// TODO Auto-generated catch block
									e1.printStackTrace();
								} 
							} else {
								System.out.println("No file selected by user." + "\n");
							}
						}
					}
				}
				);
		Download.addActionListener(
				new ActionListener(){
					public void actionPerformed(ActionEvent e){
						//Handle button action.
						if (e.getSource() == Download) {
							int returnVal = fc.showOpenDialog(Window);
							if (returnVal == JFileChooser.APPROVE_OPTION) {
								File file = fc.getSelectedFile();
								//selected file name
								downloadFileName = file.getName();
								System.out.println(downloadFileName);
								try {
									protocol.downloadFileFromServer(clientSocket, dis, downloadFileName);
								} catch (IOException ioe){
									ioe.getStackTrace();
								} 
							} else {
								System.out.println("No file selected by user." + "\n");
							}
						}
					}
				}
				);
	}

	//start
	public void  startRunning() throws Exception{
		try{
			connectToServer();						//Function to request connection to the server
			//System.out.println(uploadFileName);
			setupStreams();							//Function for setting up i/p & o/p streams
			whileConnected(dos);						//Function to implement during connection and also end connection

		} 
		catch(EOFException e){
			showMessage("\n Connection terminated!");	//When user disconnects
		} catch(IOException ioe){
			ioe.printStackTrace();
		} finally {
			//closeAllConnections();						//Function to close all streams
		}
	}

	private void whileConnected(DataOutputStream dos) throws IOException, Exception {

		X509Certificate certificate = verifyCertificate();
		//showMessage("hellooo");
		PublicKey pk = getPublic(certificate);
		protocol.setServerPubKey(pk);
		long randomNonce = protocol.generateRandomNonce();
		protocol.setRandomNonce(randomNonce);
		byte[] encryptedNonce = protocol.encrypted(randomNonce,pk);
		dos.writeInt(encryptedNonce.length);
		dos.write(encryptedNonce, 0, encryptedNonce.length);
		long encryptionNonce = protocol.getEncryptionNonce(randomNonce);
		byte[] encryptionKey = protocol.longToBytes(encryptionNonce);
		protocol.setEncryptionKey(encryptionKey);
	}

	//connect to server
	private void connectToServer() throws IOException{
		showMessage("Attempting to connect... \n");
		clientSocket = new Socket(InetAddress.getByName(ServerIP), PORT); 			// request a connection
		showMessage("Connected to: " + clientSocket.getInetAddress().getHostName()); // print the host Name that is connected
	}

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
	//set up streams
	private void setupStreams() throws IOException {
		is = clientSocket.getInputStream();
		os = clientSocket.getOutputStream();
		dos = new DataOutputStream(os);
		//fis = new FileInputStream(clientDownloadFile);
		bis = new BufferedInputStream(fis);
		dis = new DataInputStream(is);
		//fos = new FileOutputStream(clientDownloadFile);
		bos = new BufferedOutputStream(fos);
		showMessage("\n Stream are setup! \n");
		showMessage("\n ---------------------------------------"
				+ "--------------------------------------------\n");
	}



	private X509Certificate verifyCertificate() throws Exception {
		// Upload file to server
		//protocol.uploadFileToServer(socket,dos, FILENAME);

		// Download from server
		// protocol.downloadFileFromServer(socket, FILENAME);
		

		showMessage("Downloading and Verifying the certificate...\n\n");
		//protocol.downloadFileFromServer(clientSocket,dis,SERVER_CERT_PATH);


		//Verify CA Certificate
		X509Certificate c = protocol.serverVerified(SERVER_CERT_PATH);
		showMessage("Server verified succesfully!\n");
		showMessage("Use the buttons below to,\n");
		showMessage("- Upload file to the server!\n");
		showMessage("- Download file from the server!\n");

		return c;
		//System.out.println("Server public key: "+Base64.getEncoder().encode(new String(serverPubKey).getBytes()));


	}

	private PublicKey getPublic(X509Certificate c){
		PublicKey serverPublicKey = c.getPublicKey();
		return serverPublicKey;
	}

	

	//close streams and socket
	private void closeAllConnections(){
		showMessage("\n Closing Connections! \n");
		try{
			is.close();
			os.close();
			dis.close();
			fos.close();
			bos.close();
			dos.close();
			fis.close();
			bis.close();
		}catch(IOException ioe){
			ioe.printStackTrace();
		}
	}

	//add messages to window
	public static void showMessage(final String text){
		SwingUtilities.invokeLater(
				new Runnable(){
					public void run(){
						Window.append(text);						// add sent messages to the chat history window
					}
				}
				);
	}	
}

