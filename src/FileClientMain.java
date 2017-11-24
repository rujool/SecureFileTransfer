import javax.swing.JFrame;

public class FileClientMain {
	
	private static final String HOSTNAME = "127.0.0.1";
	
	public static void main(String[] args){
		FileClient client = new FileClient(HOSTNAME);										//Create new client class instance
		try {
			client.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);				//Exit the window on closing connection
			client.startRunning();												//Invoke the function to set up everything
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
		}
}
