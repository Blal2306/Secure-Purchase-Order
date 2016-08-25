import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
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
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Customer {
    
    //*********** KEYS *****************
    //public key of the bank
    static PublicKey BankPublicKey;
    //public key of the purchasing server
    static PublicKey PServerPublicKey;
    //alice public and private key pair
    static PublicKey AlicePublicKey;
    static PrivateKey AlicePrivateKey;
    //Tom public and private key pair
    static PublicKey TomPublicKey;
    static PrivateKey TomPrivateKey;
    
    //********* GLOBAL VARIABLES *********
    static String user;
    static String pass;
    static String item;
    static String quantity;
    static String creditCard;
    
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        //load all the keys from the key files
        init();
        Socket sock = null; 
        boolean valid = false;
        
        //******** S1 & S2 (PASSWORD VERIFICATION) ***********
        Scanner reader = new Scanner(System.in);
        
        //continue until user provides a valid password
        while(!valid)
        {
            //get the user name and password from the user
            System.out.print("USER NAME : ");
            user = reader.nextLine();
            System.out.print("PASSWORD : ");
            pass = generate_hash(reader.nextLine());
            
            //prepare the string for the server
            String toServer = "1,"+user+","+pass;
            
            //make a connection to the purchasing server
            sock = new Socket(args[0], Integer.parseInt(args[1]));
            
            //get input and output stream for the server
            PrintWriter out = new PrintWriter(sock.getOutputStream(),true);
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            
            //send the user name and password to the server for verification
            out.println(toServer);
            
            //get the response from the server
            String reply = in.readLine();
            
            //if the password is valid
            if(reply.equals("1"))
            {
                valid = true;
                System.out.println("Password verified with the server ......\n");
            }
            else
            {
                System.out.println("The password is incorrect ....\n");
            }
        }
        sock.close();
        
        //****************** S3 (Get the contents from the server) ************
        sock = new Socket(args[0], Integer.parseInt(args[1]));
        
        //get input and output stream for the server
        PrintWriter out = new PrintWriter(sock.getOutputStream(),true);
        BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
        
        String toServer = "2,"+user;
        out.println(toServer);
        String line = "";
        while((line = in.readLine())!= null)
        {
            System.out.println(line);
        }
        System.out.println();
        
        //ask the customer for the item number
        System.out.print("Pease enter the item # : ");
        item = reader.nextLine();
        
        //ask the customer for the quantity
        System.out.print("Please enter the quantity : ");
        quantity = reader.nextLine();
        
        //***** S4 (ENCRYPT THE ITEM, QUANTITY, CREDIT, DS AND SEND TO P SERVER ****
        //ask the customer for his credit card number
        System.out.print("Please enter the credit card number # : ");
        creditCard = reader.nextLine();
        
        //make a connection to the purchasing server
        sock = new Socket(args[0], Integer.parseInt(args[1]));
        
        //get input and output stream for the server
        out = new PrintWriter(sock.getOutputStream(),true);
        in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
        
        //to be used for digital signature     
        PrivateKey DS = get_private(user+"_key.txt");
        
        String forPServer = item+":"+quantity;
        String forPServer_enc = encode(PServerPublicKey,forPServer,1);
        
        String forBank = user+":"+creditCard;
        String forBank_enc = encode(BankPublicKey,forBank, 1);
        
        //generate the digital signature
        String DigiSig = encode(DS, user, 1);
        
        //Send the combined string to the server
        String toServer2 = "3,"+forPServer_enc+","+DigiSig+","+forBank_enc;
        out.println(toServer2);
        
        //********** S7 (FINAL REPLY FROM THE SERVER) *****************
        String res = in.readLine();
        if(res.equals("ok"))
        {
            System.out.println("\nwe will process your order soon");
            System.exit(0);
        }
        else
        {
            System.out.println("\nwrong credit card number");
            System.exit(0);
        }
        sock.close();
        //**************** END OF PROGRAM **************
    }
    public static void init() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException
    {
        BankPublicKey = get_public("bank_key.txt");
        PServerPublicKey = get_public("psystem_key.txt");
        AlicePublicKey = get_public("alice_key.txt");
        AlicePrivateKey = get_private("alice_key.txt");
        TomPublicKey = get_public("tom_key.txt");
        TomPrivateKey = get_private("tom_key.txt");
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
}
