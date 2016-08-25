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
import java.nio.file.Files;
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
import java.util.LinkedList;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Psystem {
    
    //******* KEYS ********
    static PublicKey AlicePublicKey;
    static PublicKey TomPublicKey;
    static PublicKey PSystemPublicKey;
    static PrivateKey PSystemPrivateKey;
    
    //****************
    //This will store the user name and password for the purchasing server
    //[USER, PASSWORD]
    static Map<String,String> passwords = new HashMap<String,String>();
    
    //storage for the items file
    //[ITEM #, NAME]
    static Map<Integer,String> item_name = new HashMap<Integer, String>();
    static Map<Integer,Integer> item_price = new HashMap<Integer, Integer>();
    static Map<Integer,Integer> item_quantity = new HashMap<Integer, Integer>();
    
    static String user;
    static int item;
    static int quantity;
    
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        //initialize all the keys
        init();
        load_passwordFile();
        load_itemFile();
        
        
        //start up the server
        ServerSocket listen = new ServerSocket(Integer.parseInt(args[0]));
        
        //to be used for connection to the bank
        Socket sock = null; 
        while(true)
        {
            Socket conn = listen.accept();
            
            //get the input and output stream
            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream())); 
            PrintWriter out = new PrintWriter(conn.getOutputStream(),true);
            
            //get the query from the client
            String[] fromClient = in.readLine().split(",");
            int type = Integer.parseInt(fromClient[0]);
            
            //********** S1 and S2 (Password Verification) *************
            if(type == 1)
            {
                String temp = passwords.get(fromClient[1]);
                
                //password has been verified
                if(fromClient[2].equals(temp))
                {
                    out.println(1);
                    user = fromClient[1];
                }
                else
                {
                    out.println(-1);
                }
            }
            
            //*********** S3 (Send back the Contents of the file) **************
            if(type == 2)
            {
                //the user has been verified with the password
                if(fromClient[1].equals(user))
                {
                    LinkedList toClient = new LinkedList();
                    
                    //get the contents of the item file
                    get_item(toClient);
                    out.println("ITEMS");
                    out.println("*****");
                    
                    //send the contents to the client
                    while(!toClient.isEmpty())
                    {
                        out.println(toClient.removeFirst());
                    }
                }
            }
            //************* S4 (UNPACK EVERYTHING) ***************
            if(type == 3)
            {
                String forPServer = fromClient[1];
                String DigiSig = fromClient[2];
                String forBank = fromClient[3];
                
                //verify the digital signature
                //get the public key of the user
                PublicKey customer_publicKey = get_public(user+"_key.txt");
                String signature = encode(customer_publicKey,DigiSig,0);
                
                if(signature.equals(user))
                {
                    //Unpack the stuff for the Purchasing server
                    String temp = encode(PSystemPrivateKey,forPServer,0);
                    String[] temp2 = temp.split(":");
                    //get the number of items
                    item = Integer.parseInt(temp2[0]);
                    //get the quantity
                    quantity = Integer.parseInt(temp2[1]);
                    
                    
                    //******** PREPARE THE DATA FOR THE BANK ***************
                    int tmp = item_price.get(item);
                    int price = tmp*quantity;
                    String price2 = Integer.toString(price);
                    //encrypte the price using the private key of the 
                    //purchasing server
                    String price_enc = encode(PSystemPrivateKey,price2,1);
                            
                    //make a connection to the bank
                    sock = new Socket(args[1], Integer.parseInt(args[2]));
                    
                    //get the input and output stream for the server
                    PrintWriter out2 = new PrintWriter(sock.getOutputStream(),true);
                    BufferedReader in2 = new BufferedReader(new InputStreamReader(sock.getInputStream()));
                    
                    String toBank = "5,"+user+","+price_enc+","+forBank;
                    out2.println(toBank);
                    
                    //*********** GET A REPLY FROM THE BANK *****************
                    //reply from the bank
                    String reply = in2.readLine().trim();
                    if(reply.equals("ok"))
                    {
                        //forward the message to the client
                        out.println(reply);
                        
                        //update the items list
                        int newQuantity = item_quantity.get(item);
                        newQuantity = newQuantity - quantity;
                        item_quantity.put(item, newQuantity);
                        
                        //update the contents of the file
                        dump_items();
                        
                        //terminate the server
                        System.exit(0);
                    }
                    else
                    {
                        out.println(reply);
                        System.exit(0);
                    }
                    sock.close();
                    //******************************************************
                }
                else
                {
                    System.out.println("Sorry, Signature couldn't be verified ...");
                    System.exit(0);
                }
            }
            //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            conn.close();
            
        }
    }
    public static void init() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException
    {
        AlicePublicKey = get_public("alice_key.txt");
        TomPublicKey = get_public("tom_key.txt");
        PSystemPublicKey = get_public("psystem_key.txt");
        PSystemPrivateKey = get_private("psystem_key.txt");
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
    public static void load_passwordFile() throws NoSuchAlgorithmException
    {
        String fileName = "password.txt";
        String line = null;
        try 
        {
            FileReader fileReader = new FileReader(fileName);

            BufferedReader bufferedReader = new BufferedReader(fileReader);

            while((line = bufferedReader.readLine()) != null) 
            {
                if(line.length() != 0)
                {
                    String line2 = bufferedReader.readLine();
                    String[] temp = line.split(":");
                    String user = temp[1].trim();
                    
                    String[] temp2 = line2.split(":");
                    String pass = temp2[1].trim();                    
                    passwords.put(user, pass);
                }
            }   
            bufferedReader.close();         
        }
        catch(FileNotFoundException ex) {}
        catch(IOException ex) {}
    }
    public static void load_itemFile()
    {
        String fileName = "item.txt";
        String line = null;
        try 
        {
            FileReader fileReader = new FileReader(fileName);

            BufferedReader bufferedReader = new BufferedReader(fileReader);

            while((line = bufferedReader.readLine()) != null) 
            {
                String[] temp =line.split(",");
                int index = Integer.parseInt(temp[0]);
                //insert in the name
                item_name.put(index, temp[1]);
                
                //insert the name
                int price = Integer.parseInt(temp[2].trim().substring(1));
                item_price.put(index, price);
                
                //insert the quantity
                item_quantity.put(index, Integer.parseInt(temp[3]));
            }   
            bufferedReader.close();         
        }
        catch(FileNotFoundException ex) {}
        catch(IOException ex) {}
    }
    public static void dump_items()
    {
        int size = item_name.size();
        
        //create a new file
        try 
        {
            //create a temperary file
            File file = new File("temp.txt");
            
            if (!file.exists()) 
            {
                file.createNewFile();
            }

            FileWriter fw = new FileWriter(file.getAbsoluteFile());
            BufferedWriter bw = new BufferedWriter(fw);
            for(int i = 1; i <=size; i++)
            {
                String name = item_name.get(i);
                String price = "$"+item_price.get(i);
                String quantity = item_quantity.get(i).toString();
                
                String toFile = i +","+name+","+price+","+quantity;
                
                bw.write(toFile);
                bw.newLine();
            }
            bw.close();
            
	} 
        catch (IOException e) 
        {
            e.printStackTrace();
        }
        
        
        
        //remove the old items file
        File file = new File("item.txt");
        file.delete();
        
        //rename the current file
        File oldName = new File("temp.txt");
        File newName = new File("item.txt");
        oldName.renameTo(newName);
    }
    public static void get_item(LinkedList x)
    {
        String fileName = "item.txt";
        String line = null;
        try 
        {
            FileReader fileReader = new FileReader(fileName);

            BufferedReader bufferedReader = new BufferedReader(fileReader);

            while((line = bufferedReader.readLine()) != null) 
            {
                x.add(line);
            }   
            bufferedReader.close();         
        }
        catch(FileNotFoundException ex) {}
        catch(IOException ex) {}
    }
}
