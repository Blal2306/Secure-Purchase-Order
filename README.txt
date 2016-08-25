Programming Language : Java

***********************************

Platform : bingsuns.binghamton.edu

***********************************

How to execute the Program:

1) type the command "make" to generate java class files
2) type "java Bank <bank-port>" this will start the bank server
3) type "java Psystem <purchasing-system-port> <bank-domain> <bank-port>" this will start the purchasing system server
4) type "java Customer <purchasing-system-domain> <purchasing-system-port> this will start the client

***********************************

Code for encryption/decryption : 2 overridden methods are used, the first argument can be either the public key or
the private key, the second argument is the message that we can encrypt or decrypt, the third argument is an integer
if it is 1 the return value is the encryption of the provided message, if it is 0, the return value is the decryption
of the provided message.


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

***********************************
