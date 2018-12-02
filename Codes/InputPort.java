import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;

public class InputPort {
    public static void writeCsvFile(String website, String port) {
        String COMMA_DELIMITER = ",";
        String NEW_LINE_SEPARATOR = "\n";
        FileWriter fileWriter = null;
        try {
            fileWriter = new FileWriter("C:\\Users\\Chen\\Desktop\\Seller_Port.csv", true);

            //Write a new student object list to the CSV file
            fileWriter.append(website);
            fileWriter.append(COMMA_DELIMITER);
            fileWriter.append(port);
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
    public static void main(String[] args){
        String[] websites = {
                "Amazon",
                "eBay"
        };
        String[] ports = {
                "6000",
                "1234"
        };
        for (int i = 0; i <websites.length; i++)
            writeCsvFile(websites[i], ports[i]);
    }
}
