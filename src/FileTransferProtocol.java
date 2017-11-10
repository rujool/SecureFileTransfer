import java.util.Random;

public class FileTransferProtocol {
	public static long generateRandomNonce() {
		
		Random random = new Random();
		return random.nextLong();
	}
}
