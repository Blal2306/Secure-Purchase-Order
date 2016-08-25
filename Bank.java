import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Bank {
    //***** KEYS ******
    static PublicKey PurSystemPublicKey;
    static PublicKey BankPublicKey;
    static PrivateKey BankPrivateKey;
    //*****************
    static String user;
    static int price;
    static String name;
    static String credit;
    
    static Map<String,String> balance_credit = new HashMap<String,String>();
    static Map<String,Integer> balance_bal = new HashMap<String,Integer>();
    static Map<Integer,String> balance_name = new HashMap<Integer, String>();
    
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        //initialize all the keys
        init();
        load_balance();
        
        //make a bank server
		//************************ BANK PORT # **********************************
        ServerSocket listen = new ServerSocket(Integer.parseInt(args[0]));
		//***********************************************************************
        
		System.out.println("Bank running on port "+Integer.parseInt(args[0]));
        while(true)
        {
            //listen for connection
            Socket conn = listen.accept();
			System.out.println("Connection received ...");
            
            //get the input and output stream
            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream())); 
            PrintWriter out = new PrintWriter(conn.getOutputStream(),true);
            
            //get the guery from the server
            String[] fromClient = in.readLine().split(",");
            int type = Integer.parseInt(fromClient[0]);
            
            if(type == 5)
            {
                user = fromClient[1];
                
                //get the price
                String price_temp = encode(PurSystemPublicKey,fromClient[2],0);
                price = Integer.parseInt(price_temp);
                
                //get the credit card number and the name
                String temp = encode(BankPrivateKey,fromClient[3],0);
                String[] temp2 = temp.split(":");
                name = temp2[0];
                credit = temp2[1];
                
                //+++++++ PREPARE THE RESPONSE FOR THE PURCHASING ++++++
                
                //get the credit card number for the given user
                String cardnum = balance_credit.get(name);
                
                //the card number is what is on file for the user
                if(cardnum.equals(credit))
                {
                    //update the balance
                    int currentBal = balance_bal.get(name);
                    if((currentBal - price) >= 0)
                    {
                        out.println("ok");
                        
                        currentBal = currentBal - price;
                        
                        //update the balance file
                        balance_bal.put(name, currentBal);
                        dump_balance();
                        
                        System.out.println("Balance updated for the client ...");
                    }
                    //not encough balance
                    else
                    {
                        out.println("error");
                    }
                }
                else //invalid creditcard number
                {
                    out.println("error");
                }
            }
            conn.close();
            
            //shut down the bank
            System.exit(0);
        }
    }
    public static void init() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException
    {
        PurSystemPublicKey = get_public("psystem_key.txt");
        BankPublicKey = get_public("bank_key.txt");
        BankPrivateKey = get_private("bank_key.txt");
    }
    //get the public key from the given key file name
    public static PublicKey get_public(String x) throws NoSuchAlgorithmException, InvalidKeySpecException, FileNotFoundException, IOException
    {
        PublicKey pub_key = null;
        byte[] private_key;
        String fileName = x;
        String line = null;
        try 
        {
            FileReader fileReader = new FileReader(fileName);
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            
            //ignore the first line
            line = bufferedReader.readLine();
            //second line contains the key
            line = bufferedReader.readLine();
            line = line.trim();
            String[] temp = line.split(" ");
            private_key = new byte[temp.length];
            for(int i = 0; i < temp.length; i++)
            {
                private_key[i] = (byte) Integer.parseInt(temp[i]);
            }
            bufferedReader.close(); 
            // ++++ end key read from the file ++++//
            
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pub_key = kf.generatePublic(new X509EncodedKeySpec(private_key));
            
        }
        catch(FileNotFoundException ex) {}
        catch(IOException ex) {}
        
        return pub_key;
    }
    //given the private key from the given key file
    public static PrivateKey get_private(String x) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        PrivateKey pri_key = null;
        byte[] public_key;
        String fileName = x;
        String line = null;
        try 
        {
            FileReader fileReader = new FileReader(fileName);
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            
            //READ THE PUBLIC KEY INTO BYTES
            line = bufferedReader.readLine();
            line = line.trim();
            String[] temp = line.split(" ");
            public_key = new byte[temp.length];
            for(int i = 0; i < temp.length; i++)
            {
                public_key[i] = (byte) Integer.parseInt(temp[i]);
            }
            
            bufferedReader.close(); 
            //+++ end key read from the file
            KeyFactory kf = KeyFactory.getInstance("RSA"); 
            pri_key = kf.generatePrivate(new PKCS8EncodedKeySpec(public_key));
            
        }
        catch(FileNotFoundException ex) {}
        catch(IOException ex) {}
        return pri_key;
    }
    public static String encode(PrivateKey x, String y, int m) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher cipher = Cipher.getInstance("RSA");
        String out = "";
        if(m == 1)
        {
            cipher.init(Cipher.ENCRYPT_MODE, x);
            byte[] encryptedBytes = cipher.doFinal(y.getBytes()); 
            //convert the encrypted bytes into string
            String chipertext = new String(Base64.getEncoder().encode(encryptedBytes));
            out = chipertext;
        }
        else if(m == 0)
        {
            cipher.init(Cipher.DECRYPT_MODE, x);
            //convert the encrypted plain text from string back to bytes
            byte[] ciphertextBytes = Base64.getDecoder().decode(y.getBytes());
            byte[] decryptedBytes = cipher.doFinal(ciphertextBytes);            
            String decryptedString = new String(decryptedBytes);
            out = decryptedString;
        }
        return out;
    }
    public static String encode(PublicKey x, String y, int m) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher cipher = Cipher.getInstance("RSA");
        String out = "";
        //decrypt the plaintext
        if(m == 0)
        {
            cipher.init(Cipher.DECRYPT_MODE, x);
            //convert the encrypted plain text from string back to bytes
            byte[] ciphertextBytes = Base64.getDecoder().decode(y.getBytes());
            byte[] decryptedBytes = cipher.doFinal(ciphertextBytes);            
            String decryptedString = new String(decryptedBytes);
            out = decryptedString;
        }
        else if(m == 1)
        {
            cipher.init(Cipher.ENCRYPT_MODE, x); 
            byte[] encryptedBytes = cipher.doFinal(y.getBytes()); 
            String chipertext = new String(Base64.getEncoder().encode(encryptedBytes));
            out = chipertext;
        }
        return out;
    } 
    public static String generate_hash(String x) throws NoSuchAlgorithmException
    {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(x.getBytes());
        byte[] b = md.digest();
        StringBuffer sb = new StringBuffer();
        for(byte b1: b)
        {
            sb.append(Integer.toHexString(b1 & 0xff).toString());
        }
        return sb.toString();
    }
    public static void load_balance()
    {
        String fileName = "balance.txt";
        String line = null;
        try 
        {
            FileReader fileReader = new FileReader(fileName);
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            int count = 0;

            while((line = bufferedReader.readLine()) != null) 
            {
                String[] temp = line.split(",");
                String key = temp[0].trim();
                String credit = temp[1].trim();
                int bal = Integer.parseInt(temp[2].trim());
                
                balance_name.put(count, key);
                balance_credit.put(key, credit);
                balance_bal.put(key, bal);
                count++;
            }   
            bufferedReader.close();  
        }
        catch(FileNotFoundException ex) {}
        catch(IOException ex) {}
    }
    public static void dump_balance()
    {
        int size = balance_credit.size();
        
        try 
        {
            //create a temperary file
            File file = new File("temp2.txt");
            
            if (!file.exists()) 
            {
                file.createNewFile();
            }

            FileWriter fw = new FileWriter(file.getAbsoluteFile());
            BufferedWriter bw = new BufferedWriter(fw);
            for(int i = 0; i < size; i++)
            {
                //get the key
                String key = balance_name.get(i);
                String credit = balance_credit.get(key);
                int bal = balance_bal.get(key);
                
                String toFile = key+","+credit+","+bal;
                bw.write(toFile);
                if(i != size-1)
                {
                    bw.newLine();
                }
            }
            bw.close();
            
	} 
        catch (IOException e) 
        {
            e.printStackTrace();
        }
        
        
        
        //remove the old items file
        File file = new File("balance.txt");
        file.delete();
        
        //rename the current file
        File oldName = new File("temp2.txt");
        File newName = new File("balance.txt");
        oldName.renameTo(newName);
    }
    
}
