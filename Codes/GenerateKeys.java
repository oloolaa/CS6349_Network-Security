package client;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class GenerateKeys 
{
	public static void main(String[] args) 
        {
            try 
            {
                KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(3072);
                KeyPair keyPair=keyPairGenerator.generateKeyPair();
                PublicKey publicKey=keyPair.getPublic();
                PrivateKey privateKey=keyPair.getPrivate();
                writeKeys("F:\\NS Project\\publickey_client.txt",publicKey.getEncoded());
                writeKeys("F:\\NS Project\\privatekey_client.txt",privateKey.getEncoded());
                System.out.println("Keys generated successfully");
            } 
            catch (NoSuchAlgorithmException | IOException ex) 
            {
                ex.printStackTrace();
            }
	}
        public static void writeKeys(String fileName,byte[] b) throws FileNotFoundException, IOException
        {
            FileOutputStream fos = new FileOutputStream(new File(fileName));
		fos.write(b);
		fos.flush();
		fos.close();
        }
}