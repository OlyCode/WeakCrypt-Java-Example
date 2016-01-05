// WeakCrypt.java
// Copyright 2015, Olympia Code LLC
// Author: Joseph Mortillaro
// Contact at: Olympia.Code@gmail.com
//
// All rights reserved.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.


// Note that this does not use DatatypeConverter so that it will
//    run on Android.


import java.util.*;
import java.security.MessageDigest;
import java.math.BigInteger;
import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;

class WeakCrypt {
    private byte[] key = new byte[0];
    private byte[] hash = new byte[0];
    private byte[] plaintext = new byte[0];
    private byte[] cyphertext = new byte[0];

    public static void main(String[] args) {
        System.out.println();
        WeakCrypt secret1 = new WeakCrypt();
        secret1.setPlaintext("This WeakCrypt. This is encrypted using "
        + "an SHA256 hash as a stream cypher.");
        secret1.setKey("password");
        secret1.encrypt();
        secret1.printPlaintext();
        secret1.printCyphertext();
            
        System.out.println();
        WeakCrypt secret2 = new WeakCrypt();
        secret2.setCyphertext(secret1.getCyphertext());
        secret2.setKey("password");
        secret2.decrypt();
        secret2.printCyphertext();
        secret2.printPlaintext();
        System.out.println();
    }

    public WeakCrypt() {
        setPlaintext("");
        setKey("");
    }
    
    //##################################################################
    //####   Testing Functions   #######################################
    //##################################################################
    
    //##################################################################
    //####   Utility Functions   #######################################
    //##################################################################
    public static byte[] hexStringToByteArray(String hexString) {
        final char[] hexAlphabet = "0123456789abcdef".toCharArray();
        byte[] byteArray = new byte[hexString.length()/2];
        int i = 0;
        int j = 0;
        byte[] byteTemp = new byte[2];
        while (i < byteArray.length) {
            while (j < hexAlphabet.length) {
                if (Character.toLowerCase(hexString.charAt(2*i)) == hexAlphabet[j]) {
                    byteTemp[0] = (byte) j;
                }
                if (Character.toLowerCase(hexString.charAt(2*i+1)) == hexAlphabet[j]) {
                    byteTemp[1] = (byte) j;
                }
                j++;
            }
            byteArray[i] = (byte) ((int) (byteTemp[0] << 4) + (byteTemp[1]));
            i++;
            j = 0;
        }
        return byteArray;       
    }
    
    public static String byteArrayToHexString(byte[] byteArray) {
        final char[] hexAlphabet = "0123456789abcdef".toCharArray();
        char[] returnArray = new char[byteArray.length * 2];
        for (int i = 0; i < byteArray.length; i++) {           
            byte byteTemp = byteArray[i];
            returnArray[2*i+1] = hexAlphabet[(int) (byteTemp & 0xF)];
            returnArray[2*i] = hexAlphabet[(int) (byteTemp >> 4 & 0xF)];
        }
        return new String(returnArray);
    }
       
    private static void printBytes(byte[] byteArray) {
        for (byte b : byteArray) {
            System.out.format("%02x",b);
        }
        System.out.println();
    }
    
    //##################################################################
    //####   Plaintext Functions   #####################################
    //##################################################################
    public void setPlaintext(String plaintextString) {
        try {
            this.plaintext = plaintextString.getBytes("UTF-8");
        } 
        catch(Exception e) {
            System.out.println("plaintext UTF-8 encoding not recognized");
        }
    }
    
    public String getPlaintext() {
        String plaintextString = new String(plaintext);
        return plaintextString;
    }
    
    public void printPlaintext() {
        String plaintextString = new String(plaintext);
        System.out.print("Plaintext: ");
        System.out.println(plaintextString);
    }
    
    //##################################################################
    //####   Cyphertext Functions   ####################################
    //##################################################################
    public void setCyphertext(String cyphertextString) {
        cyphertext = hexStringToByteArray(cyphertextString);
    }
    
    public String getCyphertext() {
        return byteArrayToHexString(cyphertext);
    }
    
    public void printCyphertext() {
        System.out.print("Cyphertext: ");
        System.out.println(byteArrayToHexString(cyphertext));
    }
    
    //##################################################################
    //####   Key / Hash Functions   ####################################
    //##################################################################
    public void printHash() {
        System.out.print("Hash: ");
        System.out.println(byteArrayToHexString(hash));
    }
    
    private void setHash() {
        int shaLength = 32;
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        }
        catch(Exception e) {
            System.out.println("SHA-256 not supported.");
        }
        
        int hashLength = Math.max(plaintext.length, cyphertext.length);
        hashLength = Math.max(hashLength, key.length);
        
        byte[] hashTemp;
        hashTemp = getSHA(key);
        hash = new byte[hashLength];
        
        int i = 0;
        int j = 0;
        while (i < hashLength) {
            if (j >= shaLength) {
                hashTemp = getSHA(hashTemp);
                j = 0;
            }
            hash[i] = hashTemp[j];
            i++;
            j++;
        }
    }
    
    private byte[] getSHA(byte[] byteArray) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        }
        catch(Exception e) {
            System.out.println("SHA-256 not supported.");
            return new byte[0];
        }
        
        int hashCount = 242;
        md.update(byteArray);
        byte[] digest = md.digest();
        hashCount--;
           
        for (int i = 0; i < hashCount; i++) {
            md.update(digest); 
            digest = md.digest();
        }
        return digest;
    }

    public void setKey(String key) {
        try {
            this.key = key.getBytes("UTF-8");
        } 
        catch(Exception e) {
            System.out.println("Encoding not recognized");
        }
    }
    
    //##################################################################
    //####   Encryption / Decription Functions   #######################
    //##################################################################
    public void encrypt() {
        setHash();
        cyphertext = new byte[plaintext.length];
        for (int i = 0; i < plaintext.length; i++) {
            cyphertext[i] = (byte) (((int) plaintext[i]) ^ ((int) hash[i]));
        }
    }
    
    public void decrypt() {
        setHash();
        plaintext = new byte[cyphertext.length];
        for (int i = 0; i < cyphertext.length; i++) {
            plaintext[i] = (byte) (cyphertext[i] ^ hash[i]);
        }
    }
}
    
        
    
