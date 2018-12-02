
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.Base64;

// Amazon server
public class Server {

	public static byte[] md5Java(String message) {
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] hash = md.digest(message.getBytes("UTF-8"));
			return hash;
		} catch (UnsupportedEncodingException ex) {

		} catch (NoSuchAlgorithmException ex) {

		}
		return null;
	}

	public static String readFile(String fileName) {
		BufferedReader br = null;
		String productfile = "";
		try {
			br = new BufferedReader(new FileReader(fileName));
			StringBuilder sb = new StringBuilder();
			String line = br.readLine();

			while (line != null) {
				sb.append(line);
				sb.append("\n");
				line = br.readLine();
			}
			productfile = sb.toString();
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				br.close();

			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return productfile;
	}

	public static String readCSV(String file) {
		String fileToParse = file;
		BufferedReader fileReader = null;
		String productlist = "";
		final String DELIMITER = ",";
		try {
			String line = "";
			fileReader = new BufferedReader(new FileReader(fileToParse));
			while ((line = fileReader.readLine()) != null) {
				String[] tokens = line.split(DELIMITER);
				productlist += tokens[0] + " " + tokens[1] + " " + tokens[2] + "\n";
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				fileReader.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return productlist;
	}

	public static void main(String[] args) {

		PublicKey pub_broker, pub_server;
		PrivateKey pri_server;
		ServerSocket server;
		DataOutputStream dos;
		DataInputStream dis;
		String productlist;
		Cipher c;
		SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
		String data_to_encrypt;
		String decrypted_data;
		byte[] to_send;
		byte[] encryptedData;
		String[] names;
		int port = 6000;
		System.out.println("Starting  - Amazon");
		System.out.println("Success!");
		try {
			c = Cipher.getInstance("RSA");
			server = new ServerSocket(port);
			// Get public key
			byte[] publickeyServerBytes = Files.readAllBytes(new File("D:\\publickey_amazon_server.txt").toPath());
			X509EncodedKeySpec pub_server_spec = new X509EncodedKeySpec(publickeyServerBytes);
			KeyFactory pub_server_kf = KeyFactory.getInstance("RSA");
			pub_server = pub_server_kf.generatePublic(pub_server_spec);
			System.out.println("Generating  Amazon's public key...");
			System.out.println("Success!");
			System.out.println("Amazon's public key is : " + pub_server);

			// Get private key
			byte[] privatekeyBytes = Files.readAllBytes(new File("D:\\privatekey_amazon_server.txt").toPath());
			PKCS8EncodedKeySpec pri_spec = new PKCS8EncodedKeySpec(privatekeyBytes);
			KeyFactory pri_kf = KeyFactory.getInstance("RSA");
			pri_server = pri_kf.generatePrivate(pri_spec);

			while (true) {
				// Building connection
				System.out.println("Amazon Waiting for the broker's request...");
				Socket s = server.accept();
				String time_stamp = sdf.format(new Date());
				Date d1 = sdf.parse(time_stamp);
				dis = new DataInputStream(s.getInputStream());
				dos = new DataOutputStream(s.getOutputStream());
				System.out.println("A broker starts connecting...");
				System.out.println("Success!");

				// Step 1 of phase 2: Receive Public key from Broker
				String line = dis.readUTF();
				int len = dis.readInt();
				byte[] b = new byte[len];
				dis.read(b);
				System.out.println("Receiving public key from broker...");
				X509EncodedKeySpec pub_broker_spec = new X509EncodedKeySpec(b);
				KeyFactory pub_broker_kf = KeyFactory.getInstance("RSA");
				pub_broker = pub_broker_kf.generatePublic(pub_broker_spec);
				System.out.println("Success!");
				System.out.println("The broker's public key is : " + pub_broker);

				// Step 2 of phase 2: Send Public Key to Broker
				line = "Amazon";
				dos.writeUTF(line);
				dos.writeInt(pub_server.getEncoded().length);
				dos.write(pub_server.getEncoded());
				dos.flush();
				System.out.println("Amazon Sending Public Key to the broker...");

				// Step 3 of phase 2: Verify broker
				System.out.println("Authenticating broker...");
				len = dis.readInt();
				b = new byte[len];
				dis.read(b);
				c = Cipher.getInstance("RSA");
				c.init(Cipher.DECRYPT_MODE, pri_server);
				byte[] decrypt = c.doFinal(b);
				c.init(Cipher.DECRYPT_MODE, pub_broker);
				decrypt = c.doFinal(decrypt);
				decrypted_data = new String(decrypt);
				names = decrypted_data.split(",");

				Date d2 = sdf.parse(names[1]);
                System.out.println("Receiving data from " + names[0] + " at time " + d2);
                System.out.println("Verifying " + names[0] + "...");
				long elapsed = d2.getTime() - d1.getTime();
				if (!names[0].equals("PayPal")) {
					System.out.println("Invalid request received.. Closing Connection...");
					// dos.writeUTF("Not PayPal");
					// dos.flush();
					s.close();
				} else if (elapsed > 300000) {
					dos.writeUTF("Time expired");
					dos.flush();
					System.out.println("Timer expired. Amazon Closing connection...");
					s.close();

				} else {
					dos.writeUTF("Success!");
					System.out.println(
							"Amazon Succesfully authenticated the broker. Getting session key from the broker...");
				}

				// Step 4 of phase 2: Prove myself
				System.out.println("Amazon Authenticating to the broker...");
				int i = 0;
				Random r = new Random();
				String charse = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm0123456789";
				int rr;
				StringBuilder session_string_builder = new StringBuilder();
				while (i < 16) {
					rr = r.nextInt(62);
					session_string_builder.append(charse.charAt(rr));
					i++;
				}
				String session_string = new String(session_string_builder);

				SecretKeySpec n2 = new SecretKeySpec(session_string.getBytes(), "AES");
				data_to_encrypt = session_string + "," + "Amazon";
                System.out.println("The message sending out is: " + data_to_encrypt);
				to_send = data_to_encrypt.getBytes();
				c = Cipher.getInstance("RSA");
				c.init(Cipher.ENCRYPT_MODE, pub_broker);
				encryptedData = c.doFinal(to_send);
				byte[] hashed_string = md5Java(data_to_encrypt);
				c.init(Cipher.ENCRYPT_MODE, pri_server);
				byte[] encryptedData2 = c.doFinal(hashed_string);

				dos.writeInt(encryptedData.length);
				dos.write(encryptedData);
				dos.writeInt(encryptedData2.length);
				dos.write(encryptedData2);
				System.out.println(" Success!");

				// Step 5 of phase 2: Receive the request from broker to send a list
				len = dis.readInt();
				b = new byte[len];
				dis.read(b);
				c = Cipher.getInstance("AES");
				c.init(Cipher.DECRYPT_MODE, n2);
				decrypt = c.doFinal(b);
				decrypted_data = new String(decrypt);
				names = decrypted_data.split(",");
                System.out.println("Received data from " + names[0] + " with message " + names[1]);
				if (!names[0].equals("PayPal") || !names[1].equals("send the list")) {
					System.out.println("Invalid request received.. Closing Connection...");
					dos.writeUTF("Not PayPal");
					dos.flush();
					s.close();
				} else {
					dos.writeUTF("Success!");
					System.out.println("Amazon Received a request from the broker to send my list...");

				}

				// Step 6 of phase 2: Send information to broker
				System.out.println("Amazon sending product list to the broker...");
				c = Cipher.getInstance("AES");
				productlist = readCSV("C:\\Users\\sampa\\eclipse-workspace2\\NetSecProj\\src\\productlist_amazon.csv");
				String time_stamp2 = sdf.format(new Date());
				data_to_encrypt = "Amazon," + time_stamp2;
				to_send = data_to_encrypt.getBytes();
				c = Cipher.getInstance("RSA");
				c.init(Cipher.ENCRYPT_MODE, pri_server);
				encryptedData = c.doFinal(to_send);
				String first_encrypt_string = Base64.getEncoder().encodeToString(encryptedData);
				String pub_server_string = Base64.getEncoder().encodeToString(pub_server.getEncoded());
				data_to_encrypt = first_encrypt_string + "," + productlist + "," + pub_server_string;
				to_send = data_to_encrypt.getBytes();
                System.out.println("The message sending out is: " + data_to_encrypt);
				c = Cipher.getInstance("AES");
				c.init(Cipher.ENCRYPT_MODE, n2);
				encryptedData = c.doFinal(to_send);
				dos.writeInt(encryptedData.length);
				dos.write(encryptedData);
				System.out.println("Success!");

				// Step 1 of phase 4: Get Message from Broker
				System.out.println("Amazon receiving information from the broker...");
				c = Cipher.getInstance("AES");
				c.init(Cipher.DECRYPT_MODE, n2);
				len = dis.readInt();
				b = new byte[len];
				dis.read(b);
				encryptedData = c.doFinal(b);
				decrypted_data = new String(encryptedData);
				names = decrypted_data.split(",");

				encryptedData = Base64.getDecoder().decode(names[0]);
				String amount = names[1];

				c = Cipher.getInstance("RSA");
				c.init(Cipher.DECRYPT_MODE, pri_server);

				byte[] second = c.doFinal(encryptedData);
				String result = new String(second);
				names = result.split(",");
				String product_ID = names[0];
				String session_string_2 = names[1];
				System.out.println(" Amazon Received purchase information from the broker with amount of " + amount
						+ " dollars...");
				System.out.println("Success");

				// Step 2 of phase 4: Send message to Broker.
				System.out.println("Amazon sending product to the broker...");
				String product = "";
				if (product_ID.equals("1")) {
					product = readFile("C:\\Users\\sampa\\eclipse-workspace2\\NetSecProj\\src\\product1_amazon.txt");

				}
				if (product_ID.equals("2")) {
					product = readFile("C:\\Users\\sampa\\eclipse-workspace2\\NetSecProj\\src\\product2_amazon.txt");

				}
				if (product_ID.equals("3")) {
					product = readFile("C:\\Users\\sampa\\eclipse-workspace2\\NetSecProj\\src\\product3_amazon.txt");

				}
				if (product_ID.equals("4")) {
					product = readFile("C:\\Users\\sampa\\eclipse-workspace2\\NetSecProj\\src\\product4_amazon.txt");

				}

				data_to_encrypt = product + "," + "Amazon";
				SecretKeySpec n3 = new SecretKeySpec(session_string_2.getBytes(), "AES");
				c = Cipher.getInstance("AES");
				c.init(Cipher.ENCRYPT_MODE, n3);
				to_send = data_to_encrypt.getBytes();
				encryptedData = c.doFinal(to_send);
				c.init(Cipher.ENCRYPT_MODE, n2);
				first_encrypt_string = Base64.getEncoder().encodeToString(encryptedData);
				to_send = first_encrypt_string.getBytes();
				encryptedData = c.doFinal(to_send);
				dos.writeInt(encryptedData.length);
				dos.write(encryptedData);
				System.out.println("Amazon Sent the product to the client via the broker.");
				System.out.println("Transaction completed succesfully.");
				System.out.println("----------------------------------------------------------");
				System.out.println();
			}
		}

		catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException
				| InvalidKeyException | IllegalBlockSizeException | BadPaddingException | ParseException ex) {
			ex.printStackTrace();
		}

	}

}
