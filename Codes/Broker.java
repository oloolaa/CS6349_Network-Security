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
import java.util.*;

public class Broker {
	public static HashMap<String, String> readUserPass(String file) {
		HashMap<String, String> map = new HashMap<>();
	    String fileToParse = file;
	    BufferedReader fileReader = null;
	    final String DELIMITER = ",";
	    try {
	        String line = "";
	        fileReader = new BufferedReader(new FileReader(fileToParse));
	        while ((line = fileReader.readLine()) != null) {
	            String[] tokens = line.split(DELIMITER);
	            for(int i = 0; i < tokens.length - 1; i++) {
	                map.put(tokens[i], tokens[i + 1]);
	            }
	        }
	    }
	    catch (Exception e) {
	    	e.printStackTrace();
	    }
	    finally {
	    	try {
	    		fileReader.close();
	    	} 
	    	catch (IOException e) {
	    		e.printStackTrace();
	    	}
	    }
		return map;
	}
    public static HashMap<String, Integer> readPort(String file) {
        HashMap<String, Integer> map = new HashMap<>();
        String fileToParse = file;
        BufferedReader fileReader = null;
        final String DELIMITER = ",";
        try {
            String line = "";
            fileReader = new BufferedReader(new FileReader(fileToParse));
            while ((line = fileReader.readLine()) != null) {
                String[] tokens = line.split(DELIMITER);
                for(int i = 0; i < tokens.length - 1; i++) {
                    map.put(tokens[i], Integer.valueOf(tokens[i + 1]));
                }
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        finally {
            try {
                fileReader.close();
            }
            catch (IOException e) {
                e.printStackTrace();
            }
        }
        return map;
    }
    public static void writeCsvFile(String user, String time, String amount, String tranID, int rr) {
        String COMMA_DELIMITER = ",";
        String NEW_LINE_SEPARATOR = "\n";
        String fileName = "C:\\Users\\Chen\\Desktop\\id.time.amount.transactionID.receipt.csv";
        FileWriter fileWriter = null;
        try {
            fileWriter = new FileWriter(fileName, true);
            fileWriter.append(user);
            fileWriter.append(COMMA_DELIMITER);
            fileWriter.append(time);
            fileWriter.append(COMMA_DELIMITER);
            fileWriter.append(amount);
            fileWriter.append(COMMA_DELIMITER);
            fileWriter.append(Integer.toString(rr));
            fileWriter.append(COMMA_DELIMITER);
            fileWriter.append(tranID);
            fileWriter.append(NEW_LINE_SEPARATOR);
            System.out.println("Adding purchase record...");
            System.out.println("Success!");

        }
        catch (Exception e) {
            System.out.println("Error in CsvFileWriter.");
            e.printStackTrace();
        }
        finally {
            try {
                fileWriter.flush();
                fileWriter.close();
            }
            catch (IOException e) {
                System.out.println("Error while flushing/closing fileWriter.");
                e.printStackTrace();
            }
        }
    }
    public static byte[] md5Java(String message){
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(message.getBytes("UTF-8"));
            return hash;
        }
        catch (UnsupportedEncodingException ex) {
        }
        catch (NoSuchAlgorithmException ex) {
        }
        return null;
    }
	
    public static void main(String[] args){
        // All these variables.
        PublicKey pub_client, pub_broker, pub_server;
        PrivateKey pri_broker;
        ServerSocket server;
        DataOutputStream dos;
        DataInputStream dis;
        DataOutputStream dos2;
        DataInputStream dis2;
        Cipher c;
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
        String data_to_encrypt;
        String decrypted_data;
        byte[] to_send;
        byte[] encryptedData;
        String[] names;
        int port = 5000;
        Map<String, String> user_pwd = readUserPass("C:\\Users\\Chen\\Desktop\\User_Password.csv");
        Map<String, Integer> websites = readPort("C:\\Users\\Chen\\Desktop\\Seller_Port.csv");

        System.out.println("Starting broker system...");
        System.out.println("Success!");

        try {
            // Get public key
            byte[] publickeyBrokerBytes = Files.readAllBytes(new File("C:\\Users\\Chen\\Desktop\\publickey_broker.txt").toPath());
            X509EncodedKeySpec pub_broker_spec = new X509EncodedKeySpec(publickeyBrokerBytes);
            KeyFactory pub_broker_kf = KeyFactory.getInstance("RSA");
            pub_broker = pub_broker_kf.generatePublic(pub_broker_spec);
            System.out.println("Generating broker's public key...");
            System.out.println("Success!");
            System.out.println("The broker's public key is : " + pub_broker);

            // Get private key
            byte[] privatekeyBytes = Files.readAllBytes(new File("C:\\Users\\Chen\\Desktop\\privatekey_broker.txt").toPath());
            PKCS8EncodedKeySpec pri_spec = new PKCS8EncodedKeySpec(privatekeyBytes);
            KeyFactory pri_kf = KeyFactory.getInstance("RSA");
            pri_broker = pri_kf.generatePrivate(pri_spec);

            // Open the server of PayPal.
            server = new ServerSocket(port);

            while (true){
                // Building connection.
                c = Cipher.getInstance("RSA");
                System.out.println("Waiting for client request...");
                Socket s = server.accept();
                String time_stamp = sdf.format(new Date());
                Date d1 = sdf.parse(time_stamp);
                dis = new DataInputStream(s.getInputStream());
                dos = new DataOutputStream(s.getOutputStream());
                System.out.println("A client starts connecting...");
                System.out.println("Success!");

                // Step 1 of phase 1: receive public key from client. {Alice, len, public key}.
                String line = dis.readUTF();
                int len = dis.readInt();
                byte[] b = new byte[len];
                dis.read(b);
                System.out.println("Receiving public key from client...");
                X509EncodedKeySpec pub_client_spec = new X509EncodedKeySpec(b);
                KeyFactory pub_client_kf = KeyFactory.getInstance("RSA");
                pub_client = pub_client_kf.generatePublic(pub_client_spec);
                System.out.println("Success!");
                System.out.println("This client's public key is: " + pub_client);

                // Step 2 of phase 1: send public key from broker.
                line = "Paypal";
                dos.writeUTF(line);
                dos.writeInt(pub_broker.getEncoded().length);
                dos.write(pub_broker.getEncoded());
                dos.flush();
                System.out.println("Sending public key to client...");
                System.out.println("Success!");

                // Step 3 of phase 1: confirm user information.
                len = dis.readInt();
                b = new byte[len];
                dis.read(b);
                c.init(Cipher.DECRYPT_MODE, pri_broker);
                byte[] decrypt = c.doFinal(b);
                decrypted_data = new String(decrypt);
                names = decrypted_data.split(",");                  // usr, pwd, time.

                Date d2 = sdf.parse(names[2]);
                long elapsed = d2.getTime() - d1.getTime();
                if (elapsed>300000){
                    dos.writeUTF("Timestamp expired");
                    dos.flush();
                    System.out.println("Login time expired. Closing connection...");
                    continue;
                }

                String hashOfPwd = Base64.getEncoder().encodeToString(md5Java(names[1]));
                if (!user_pwd.containsKey(names[0]) || (user_pwd.containsKey(names[0]) && !user_pwd.get(names[0]).equals(hashOfPwd))){
                    dos.writeUTF("Invalid");
                    dos.flush();
                    System.out.println("Failed to log in. Closing connection...");
                    continue;
                }
                else {
                    dos.writeUTF("Success");
                    System.out.println("Client logging in...");
                    System.out.println("Success!");
                    dos.flush();
                }
                String username = names[0];

                // Step 4 of phase 1: successfully log in. Generating session key.
                int i = 0;
                Random r = new Random();
                String charse = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm0123456789";
                int rr;
                StringBuilder session_string_builder = new StringBuilder();
                while (i < 16){
                    rr = r.nextInt(62);
                    session_string_builder.append(charse.charAt(rr));
                    i++;
                }

                String session_string = new String(session_string_builder);
                data_to_encrypt = names[0] + ",PayPal," + session_string;
                to_send = data_to_encrypt.getBytes();
                c = Cipher.getInstance("RSA");
                c.init(Cipher.ENCRYPT_MODE, pri_broker);
                encryptedData = c.doFinal(to_send);

                c = Cipher.getInstance("RSA");
                c.init(Cipher.ENCRYPT_MODE, pub_client);
                encryptedData = c.doFinal(encryptedData);
                dos.writeInt(encryptedData.length);
                dos.write(encryptedData);

                System.out.println("Sending session key to the client...");
                System.out.println("Success!");
                System.out.println("The message sending to the client is: " + data_to_encrypt);

                String close = dis.readUTF();
                if (close.equals("Close")){
                    System.out.println("Client closes the connection...");
                    System.out.println("Success!");
                    s.close();
                    continue;
                }

                // Step 5 of phase 1: getting information from client.
                len = dis.readInt();
                b = new byte[len];
                dis.read(b);
                SecretKeySpec n1 = new SecretKeySpec(session_string.getBytes(),"AES");
                c = Cipher.getInstance("AES");
                c.init(Cipher.DECRYPT_MODE, n1);
                decrypt = c.doFinal(b);
                decrypted_data = new String(decrypt);
                System.out.println("Receiving seller's name from client...");
                System.out.println("Success!");
                System.out.println("Client sends server name: " + decrypted_data);

                boolean flag = false;
                if (!websites.containsKey(decrypted_data)){
                    dos.writeUTF("Input again");
                    System.out.println("Client sends wrong seller name. Waiting for client's input...");
                    for (int t = 1; t < 6; t++){
                        len = dis.readInt();
                        b = new byte[len];
                        dis.read(b);
                        decrypt = c.doFinal(b);
                        decrypted_data = new String(decrypt);
                        System.out.println("Receiving seller's name from client...");
                        System.out.println("Success!");
                        System.out.println("Client sends server name: " + data_to_encrypt);

                        if (websites.containsKey(decrypted_data))
                            break;
                        else if (t < 5 && !websites.containsKey(decrypted_data)){
                            System.out.println("Client sends wrong seller name. Waiting for client's input...");
                            dos.writeUTF("Input again");
                        }
                        else if (t == 5){
                            dos.writeUTF("No such server");
                            flag = true;
                            break;
                        }
                    }
                }
                else
                    dos.writeUTF("Success!");

                if (flag){
                    System.out.println("False input for several times. Closing connection...");
                    System.out.println("Success!");
                    s.close();
                    continue;
                }

                Socket s2 = new Socket("25.7.198.37", websites.get(decrypted_data));
                System.out.println("Connecting to seller...");
                System.out.println("Success!");
                dis2 = new DataInputStream(s2.getInputStream());
                dos2 = new DataOutputStream(s2.getOutputStream());
                String time_stamp2 = sdf.format(new Date());

                // Step 1 of phase 2: send out public key.
                line = "PayPal";
                dos2.writeUTF(line);
                dos2.writeInt(pub_broker.getEncoded().length);
                dos2.write(pub_broker.getEncoded());
                dos2.flush();
                System.out.println("Sending public key to seller...");
                System.out.println("Success!");

                // Step 2 of phase 2: Get public key from Seller.
                line = dis2.readUTF();
                if (!line.equals(decrypted_data)){
                    s2.close();
                }
                len = dis2.readInt();
                b = new byte[len];
                dis2.read(b);
                System.out.println("Receiving public key from seller...");
                System.out.println("Success!");
                X509EncodedKeySpec pub_server_spec = new X509EncodedKeySpec(b);
                KeyFactory pub_server_kf = KeyFactory.getInstance("RSA");
                pub_server = pub_server_kf.generatePublic(pub_server_spec);
                System.out.println("Seller's public key is: " + pub_server);

                // Step 3 of phase 2: proving myself.
                System.out.println("Authenticating to the seller...");
                data_to_encrypt = "PayPal," + time_stamp2;
                System.out.println("The message sending out is: " + data_to_encrypt);
                to_send = data_to_encrypt.getBytes();
                c = Cipher.getInstance("RSA");
                c.init(Cipher.ENCRYPT_MODE, pri_broker);
                encryptedData = c.doFinal(to_send);

                c.init(Cipher.ENCRYPT_MODE, pub_server);
                encryptedData = c.doFinal(encryptedData);
                dos2.writeInt(encryptedData.length);
                dos2.write(encryptedData);

                String read = dis2.readUTF();
                if (!read.equals("Success!")){
                    System.out.println("Authentication time expired. Closing connection...");
                    System.out.println("Success!");
                    s2.close();
                }
                else {
                    System.out.println("Success!");
                }

                // Step 4 of phase 2: verify server.
                len = dis2.readInt();
                b = new byte[len];
                dis2.read(b);
                c = Cipher.getInstance("RSA");
                c.init(Cipher.DECRYPT_MODE, pri_broker);
                decrypt = c.doFinal(b);
                decrypted_data = new String(decrypt);

                String[] temp =decrypted_data.split(",");
                System.out.println("Receiving data from " + temp[1] + "...");
                System.out.println("Verifying " + temp[1] + "...");

                byte[] hash_check = md5Java(decrypted_data);
                len = dis2.readInt();
                b = new byte[len];
                dis2.read(b);
                c = Cipher.getInstance("RSA");
                c.init(Cipher.DECRYPT_MODE, pub_server);
                decrypt = c.doFinal(b);

                boolean hashCheck = true;
                for (i = 0; i < hash_check.length; i++){
                    if (hash_check[i] != decrypt[i]){
                        hashCheck = false;
                        break;
                    }
                }
                if (!hashCheck){
                    System.out.println("Failed to connect " + temp[1] + ". Closing connection...");
                    s2.close();
                    continue;
                }
                System.out.println("Seller verified!");

                // Step 5 of phase 2: Send the request to Amazon.
                System.out.println("Sending request to seller...");
                names = decrypted_data.split(",");
                SecretKeySpec n2 = new SecretKeySpec(names[0].getBytes(),"AES");
                c = Cipher.getInstance("AES");
                data_to_encrypt = "PayPal,send the list";
                to_send = data_to_encrypt.getBytes();
                c.init(Cipher.ENCRYPT_MODE, n2);
                encryptedData = c.doFinal(to_send);
                dos2.writeInt(encryptedData.length);
                dos2.write(encryptedData);

                read = dis2.readUTF();
                if (!read.equals("Success!")){
                    System.out.println("Session corrupted. Closing connection...");
                    s2.close();
                }
                else {
                    System.out.println("Success!");
                    System.out.println("The message sending out is: " + data_to_encrypt);
                }

                // Step 6 of phase 2: Get the information from Amazon.
                System.out.println("Receiving list from seller...");
                c = Cipher.getInstance("AES");
                c.init(Cipher.DECRYPT_MODE, n2);
                len = dis2.readInt();
                b = new byte[len];
                dis2.read(b);
                decrypt = c.doFinal(b);
                System.out.println("Success!");

                // Step 1 of phase 3: send the message to client.
                System.out.println("Sending list to client...");
                c = Cipher.getInstance("AES");
                c.init(Cipher.ENCRYPT_MODE, n1);
                to_send = decrypt;
                encryptedData = c.doFinal(to_send);
                dos.writeInt(encryptedData.length);
                dos.write(encryptedData);
                System.out.println("Success!");

                close = dis.readUTF();
                if (close.equals("Close")){
                    System.out.println("List out of date. Closing connection...");
                    s.close();
                    continue;
                }

                // Step 2 of phase 3: get information from client and save it as TransactionID.
                System.out.println("Receiving purchase information from client...");
                c = Cipher.getInstance("AES");
                c.init(Cipher.DECRYPT_MODE, n1);
                len = dis.readInt();
                b = new byte[len];
                dis.read(b);
                byte[] first_decrypt = c.doFinal(b);
                rr = r.nextInt(Integer.MAX_VALUE);          // Number of TranID.
                String tranID = Base64.getEncoder().encodeToString(first_decrypt);

                c = Cipher.getInstance("RSA");
                c.init(Cipher.DECRYPT_MODE, pub_client);
                byte[] second_decrypt = c.doFinal(first_decrypt);
                decrypted_data = new String(second_decrypt);
                names = decrypted_data.split(",");          // amount, 'things directly send to server'.
                String amount = names[0];
                System.out.println("Success!");

                String new_time = sdf.format(d1);
                writeCsvFile(username, new_time, amount, tranID, rr);

                // Step 1 of phase 4: Send message to server.
                data_to_encrypt = names[1] + "," + names[0];
                c = Cipher.getInstance("AES");
                c.init(Cipher.ENCRYPT_MODE, n2);
                to_send = data_to_encrypt.getBytes();
                encryptedData = c.doFinal(to_send);
                dos2.writeInt(encryptedData.length);
                dos2.write(encryptedData);
                System.out.println("Sending purchase information to seller. Paying amount of " + amount + " dollars...");
                System.out.println("Success!");

                // Step 2 of phase 4: get message from server.
                System.out.println("Receiving product from the seller...");
                c = Cipher.getInstance("AES");
                c.init(Cipher.DECRYPT_MODE, n2);
                len = dis2.readInt();
                b = new byte[len];
                dis2.read(b);
                decrypt = c.doFinal(b);
                decrypted_data = new String(decrypt);
                System.out.println("Success!");
                System.out.println("The package is: " + decrypted_data);


                // Step 1 of phase 5: send message to client.
                System.out.println("Sending product from the seller...");
                c = Cipher.getInstance("AES");
                c.init(Cipher.ENCRYPT_MODE, n1);
                data_to_encrypt = decrypted_data + "," + rr;
                System.out.println("The package is: " + data_to_encrypt);
                to_send = data_to_encrypt.getBytes();
                encryptedData = c.doFinal(to_send);
                dos.writeInt(encryptedData.length);
                dos.write(encryptedData);
                System.out.println("Success!");

                close = dis.readUTF();
                if (close.equals("Close")){
                    s.close();
                    continue;
                }

                System.out.println("Product transferred successfully.");
                System.out.println("Finished serving client.");
                System.out.println("----------------------------------------------------------");
                System.out.println();
                //close the ServerSocket object
                s.close();
            }
        }
        catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | ParseException ex) {
            ex.printStackTrace();
        }
    }
}
