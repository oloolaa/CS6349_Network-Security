import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class InputUserPwd {
    // Write csv file.
    public static void writeCsvFile(String username, String password) {
        String COMMA_DELIMITER = ",";
        String NEW_LINE_SEPARATOR = "\n";
        FileWriter fileWriter = null;
        try {
            fileWriter = new FileWriter("C:\\Users\\Chen\\Desktop\\User_Password.csv", true);

            //Write a new student object list to the CSV file
            fileWriter.append(username);
            fileWriter.append(COMMA_DELIMITER);
            fileWriter.append(password);
            fileWriter.append(NEW_LINE_SEPARATOR);

            System.out.println("Add one successfully.");

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

    // Compare md5-hash value.
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

    public static void main(String[] args) {
        String[] username = {
                "Alice",
                "Bob"
        };
        String[] password = {
                "1234",
                "5678"
        };
        for (int i = 0; i < username.length; i++)
            writeCsvFile(username[i], Base64.getEncoder().encodeToString(md5Java(password[i])));
    }
}
