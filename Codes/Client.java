import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Client 
{
    public static void main(String[] args)
    {
        //Declare all the variables.
        PublicKey pub_client,pub_broker,pub_server;
        PrivateKey pri_client;
        Socket s;
        DataOutputStream dos;
        DataInputStream dis;
        Cipher c;
        SimpleDateFormat sdf=new SimpleDateFormat("HH:mm:ss");

        String data_to_encrypt;
        String decrypted_data;
        byte[] to_send;
        byte[] encryptedData;
        String[] names;
        byte[] b;
        
        try
        {
            System.out.println("Starting client");
            System.out.println("Success");
                //Get the time stamp when establishing connection
                String time_stamp= sdf.format(new Date());
                Date d1=sdf.parse(time_stamp);
                c=Cipher.getInstance("RSA");
                
                
            //Get public key of client from the file
                byte[] publickeyClientBytes = Files.readAllBytes(new File("F:\\NS Project\\publickey_client.txt").toPath());
                X509EncodedKeySpec pub_client_spec = new X509EncodedKeySpec(publickeyClientBytes);
                KeyFactory pub_client_kf = KeyFactory.getInstance("RSA");
                pub_client=pub_client_kf.generatePublic(pub_client_spec);
                System.out.println("The client's public key is : "+pub_client);
                
            //Get private key of client from the file
                byte[] privatekeyBytes = Files.readAllBytes(new File("F:\\NS Project\\privatekey_client.txt").toPath());
                PKCS8EncodedKeySpec pri_spec = new PKCS8EncodedKeySpec(privatekeyBytes);
                KeyFactory pri_kf = KeyFactory.getInstance("RSA");
                pri_client=pri_kf.generatePrivate(pri_spec);

                s=new Socket("25.7.145.154",5000);
                System.out.println("Connected to broker");
                
                dis=new DataInputStream(s.getInputStream());
                dos=new DataOutputStream(s.getOutputStream());
                System.out.println("Successfully connected");
                
            //Step 1 of phase 1: Send public key to broker
                System.out.println("Sending public key to the broker");
                String line="Alice";
                dos.writeUTF(line);
                dos.writeInt(pub_client.getEncoded().length);
                dos.write(pub_client.getEncoded());
                dos.flush();
                System.out.println("Success");
                
            //Step 2 of phase 1: Get public key of broker
                System.out.println("Receiving public key from the broker");
                line=dis.readUTF();
                int len=dis.readInt();
                b=new byte[len];
                dis.read(b);
                X509EncodedKeySpec pub_broker_spec = new X509EncodedKeySpec(b);
                KeyFactory pub_broker_kf = KeyFactory.getInstance("RSA");
                pub_broker=pub_broker_kf.generatePublic(pub_broker_spec);    
                System.out.println("Success");
                System.out.println("The broker's public key is : " + pub_broker);
                
            //Step 3 of phase 1: Send login details to broker
                System.out.println("Authenticating myself to the broker");
                BufferedReader br=new BufferedReader(new InputStreamReader(System.in));
                System.out.print("Enter username : ");
                String user_name=br.readLine();
                System.out.print("Enter password : ");
                String password=br.readLine();
                data_to_encrypt=user_name+","+password+","+time_stamp;
                to_send=data_to_encrypt.getBytes();
                c.init(Cipher.ENCRYPT_MODE,pub_broker);
                encryptedData=c.doFinal(to_send);
                dos.writeInt(encryptedData.length);
                dos.write(encryptedData);
                
                //Check if the login credentials are correct and the packet is within the time frame (5 minutes)
                line=dis.readUTF();
                if(line.equals("Timestamp expired"))
                {
                    System.out.println("Time stamp exceeded");
                    s.close();
                    System.exit(0);
                }
                if(line.equals("Invalid"))
                {
                    System.out.println("Invalid login");
                    s.close();
                    System.exit(0);
                }
                System.out.println("Login successful");
                
            //Step 4 of phase 1 : Get session key from the broker
                len=dis.readInt();
                b=new byte[len];
                dis.read(b);
                c.init(Cipher.DECRYPT_MODE, pri_client);
                byte[] first_decrypt=c.doFinal(b);
                c.init(Cipher.DECRYPT_MODE, pub_broker);
                byte[] second_decrypt=c.doFinal(first_decrypt);
                decrypted_data=new String(second_decrypt);
                names=decrypted_data.split(",");
                
                //Check if the message is tampered or not.
                if(!names[0].equals("Alice")||!names[1].equals("PayPal"))
                {
                    System.out.println("Session tampered");
                    dos.writeUTF("Close");
                    s.close();
                    System.exit(0);
                }
                dos.writeUTF("Success");
                System.out.println("Broker authenticated successfully. Getting session key from the broker");
                System.out.println("Data received from broker is : "+decrypted_data);
                System.out.print("Enter the seller name : ");
                String seller=br.readLine();
                
            //Step 5 of phase 1 : Encrypt the data with session key
                System.out.println("Sending seller name to broker");
                SecretKeySpec session_key_broker=new SecretKeySpec(names[2].getBytes(),"AES");
                c=Cipher.getInstance("AES");
                data_to_encrypt=seller;
                to_send=data_to_encrypt.getBytes();
                c.init(Cipher.ENCRYPT_MODE, session_key_broker);
                encryptedData=c.doFinal(to_send);
                dos.writeInt(encryptedData.length);
                dos.write(encryptedData);  
                String result=dis.readUTF();
                
                while(!result.equals("Success!"))
                {
                    if(result.equals("Input again"))
                    {
                        System.out.println("Wrong server name. Try again");
                        System.out.print("Enter the seller name : ");
                        seller=br.readLine();
                        data_to_encrypt=seller;
                        to_send=data_to_encrypt.getBytes();
                        c.init(Cipher.ENCRYPT_MODE, session_key_broker);
                        encryptedData=c.doFinal(to_send);
                        dos.writeInt(encryptedData.length);
                        dos.write(encryptedData);
                        result=dis.readUTF();
                    }
                    else if(result.equals("No such server"))
                    {
                        System.out.println("Max tries exceeded. Closing connection");
                        s.close();
                        System.exit(0);
                    }
                }
                System.out.println("Encrypting the data with the session key of the broker");
                System.out.println("Success");
                System.out.println("Data sent to broker : "+seller);
                
            //Step 1 of phase 3: Verify seller, get the list and public key of seller
                System.out.println("Authenticating seller...");
                c=Cipher.getInstance("AES");
                c.init(Cipher.DECRYPT_MODE, session_key_broker);
                len=dis.readInt();
                b = new byte[len];
                dis.read(b);
                first_decrypt=c.doFinal(b);
                decrypted_data=new String(first_decrypt);
                names=decrypted_data.split(",");
                first_decrypt=Base64.getDecoder().decode(names[0]);
                String list=names[1];
            //Get public key of seller
                byte[] publickeyServerBytes =Base64.getDecoder().decode(names[2]);
                X509EncodedKeySpec pub_server_spec = new X509EncodedKeySpec(publickeyServerBytes);
                KeyFactory pub_server_kf = KeyFactory.getInstance("RSA");
                pub_server=pub_server_kf.generatePublic(pub_server_spec);
                c=Cipher.getInstance("RSA");
                c.init(Cipher.DECRYPT_MODE, pub_server);
                second_decrypt=c.doFinal(first_decrypt);
                result=new String(second_decrypt);
                names=result.split(",");
                //Check if the message is tampered or not.
                if(!names[0].equals(seller))
                {
                    System.out.println("Session corrupted. Closing connection");
                    dos.writeUTF("Close");
                    s.close();
                    System.exit(0);
                }
                //Check if the received message is within the time frame or not
                Date d2=sdf.parse(names[1]);
                long elapsed = d2.getTime() - d1.getTime(); 
                if(elapsed>300000)
                {
                    System.out.println("Closing connection");
                    dos.writeUTF("Close");
                    s.close();
                    System.exit(0);
                }
                dos.writeUTF("Success");
                System.out.println("Seller authenticated successfully");
                System.out.println("Data received from seller via broker : "+result);
                
            //Step 2 of phase 3: Send amount, product ID and generate session key for the seller
                System.out.println("List received");
                System.out.println("This is the list provided by "+seller);
                System.out.println(list);
                String[] products=list.split("\n");
                String[] item_details;
                String amount="",product_id="";
                int i;
                boolean flag=true;
                while(flag)
                {
                    System.out.print("Select the product ID : ");
                    product_id=br.readLine();
                    for(i=0;i<products.length;i++)
                    { 
                        item_details=products[i].split(" ");
                        if(item_details[0].equals(product_id))
                        {
                         amount=item_details[2];
                         flag=false;
                         break;
                        }
                    }
                    if(i==products.length)
                    {
                        System.out.println("Enter valid product id");
                    }
                }
                i=0;
                //Generate session key
                Random r=new Random();
                String charse="QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm0123456789";
                int rr;
                StringBuilder session_string_builder=new StringBuilder();
                while(i<16)
                {
                    rr=r.nextInt(62);
                    session_string_builder.append(charse.charAt(rr));
                    i++;
                }
                String session_string=new String(session_string_builder);
                data_to_encrypt=product_id+","+session_string;
                to_send=data_to_encrypt.getBytes();
                c=Cipher.getInstance("RSA");
                c.init(Cipher.ENCRYPT_MODE, pub_server);
                encryptedData=c.doFinal(to_send);
                String first_encrypt_string=Base64.getEncoder().encodeToString(encryptedData);
                data_to_encrypt=amount+","+first_encrypt_string;
                to_send=data_to_encrypt.getBytes();
                c.init(Cipher.ENCRYPT_MODE, pri_client);
                encryptedData=c.doFinal(to_send);
                c=Cipher.getInstance("AES");
                c.init(Cipher.ENCRYPT_MODE, session_key_broker);
                byte[] second_encrypt=c.doFinal(encryptedData);
                dos.writeInt(second_encrypt.length);
                dos.write(second_encrypt);
                System.out.println("Sending the product ID and the amount to the seller");
                System.out.println("Success");

                //Step 1 of phase 5: Get the product and the transaction ID
                SecretKeySpec session_key_server=new SecretKeySpec(session_string.getBytes(),"AES");
                len=dis.readInt();
                b = new byte[len];
                dis.read(b);
                c=Cipher.getInstance("AES");
                c.init(Cipher.DECRYPT_MODE, session_key_broker);
                first_decrypt=c.doFinal(b);
                line=new String(first_decrypt);
                names=line.split(",");
                String transaction_id=names[1];
                byte[] to_decrypt =Base64.getDecoder().decode(names[0]);
                c.init(Cipher.DECRYPT_MODE, session_key_server);
                second_decrypt=c.doFinal(to_decrypt);
                names=new String(second_decrypt).split(",");
                if(!names[1].equals(seller))
                {
                    System.out.println("The message has been tampered. Closing connection");
                    dos.writeUTF("Close");
                    s.close();
                    System.exit(0);
                }
                dos.writeUTF("Success");
                String product=names[0];
                BufferedWriter bw=new BufferedWriter(new FileWriter("F:\\NS Project\\"+product_id+"_"+seller+"_"+transaction_id+".txt"));
                bw.write(product);
                bw.flush();
                bw.close();
                System.out.println("The product has been successfully downloaded into your system. The transaction ID is "+transaction_id);

                System.out.println("Thank You for shopping with "+seller+".Have a nice day!!!");
                s.close();
        }

        catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | ParseException ex)
        {
            ex.printStackTrace();
        }
    }
}