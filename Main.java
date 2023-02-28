import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

//Demonstration of a PGP type encryption
//Mitch Watson
//Lab 6.5
//i was a bit disapointed by the "encryption" lab so i decided to do it better

public class Main {
    public static void main(String[] args) throws IOException, GeneralSecurityException {
        Scanner scan = new Scanner(System.in);
        byte[] target, out;
        boolean running = true, automatic = false;
        PublicKey pubkey;
        PrivateKey prvkey;
        while (running) {
            System.out.println("               PGP Encypter");
            System.out.println("---------------------------------------");
            System.out.println("Type associated number for output");
            System.out.println("---------------------------------------");
            System.out.println("  1 - Generate Keypair");
            System.out.println("  2 - Encrypt File");
            System.out.println("  3 - Decrypt File");
            System.out.println("  4 - Read Public Key File");
            System.out.println("  5 - Read Private Key File");
            System.out.println("  6 - Run instructions File");
            System.out.println("  7 - About");
            System.out.println("  8 - Exit Program");

            switch (scan.nextInt()) {

                case 1:
                    System.out.println("Generating keypair...");
                    KeyPair keys = JavaPGP.generateKeyPair();
                    System.out.println("Keypair generated.");
                    System.out.println("Local path to Public key file");
                    WriteFile(scan.next(),keys.getPublic().getEncoded());
                    System.out.println("Local path to Private key file");
                    WriteFile(scan.next(),keys.getPrivate().getEncoded());
                    break;
                case 2:
                    System.out.println("Local path to Target Encryption file : ");
                    target = ReadFile(scan.next());
                    System.out.println("Local path to Public key : ");
                    pubkey = JavaPGP.getPublicKey(ReadFile(scan.next()));
                    System.out.println("Beginnining Encryption");
                    out = JavaPGP.encrypt(target,pubkey);
                    System.out.println("Local path to Encryption output");
                    WriteFile(scan.next(),out);
                    break;
                case 3:
                    System.out.println("Local path to Target Decryption file : ");
                    target = ReadFile(scan.next());
                    System.out.println("Local path to Private key : ");
                    prvkey = JavaPGP.getPrivateKey(ReadFile(scan.next()));
                    System.out.println("Beginnining Decryption");
                    out = JavaPGP.decrypt(target,prvkey);
                    System.out.println("Local path to Decryption output");
                    WriteFile(scan.next(),out);
                    break;                    
                case 4:
                    System.out.println("Local path to Public key file");
                    System.out.println(JavaPGP.getPublicKey(ReadFile(scan.next())));
                    break;
                case 5:
                    System.out.println("Local path to Private key file");
                    System.out.println(JavaPGP.getPrivateKey(ReadFile(scan.next())));
                    break;
                case 6 :
                    System.out.println("Local path to Instructions file");
                    File s = new File(System.getProperty("user.dir") + "//" + scan.next());
                    scan = new Scanner(s);
                    automatic = true;
                    break;
                case 7 : 
                    System.out.println("PGP encryption is a modern asymetric key cryptography algorthim");
                    System.out.println("Asymetric encryption means that you can only encode text with the");
                    System.out.println("Public key, and you can only decode using the private key.");
                    System.out.println("This is useful when communicating over the internet where anyone");
                    System.out.println("could read the text you send, only the recipant with the private");
                    System.out.println("key.");
                    System.out.println("For this implementation Text is first encrypted with an AES key,");
                    System.out.println("AES or the Advanced Encryption Standard is a symetric encryption");
                    System.out.println("algorthim, meaning the same key can be used to encrypt and decrypt");
                    System.out.println("text.");
                    System.out.println("");
                    System.out.println("[enter anything to continue]");
                    scan.next();
                    System.out.println("");
                    System.out.println("To encrypt a file the computer first generates an AES key and encypts");
                    System.out.println("the file, the AES key is then encrypted using the PGP Public key.");
                    System.out.println("The AES encrypted message and the PGP encrypted AES key");
                    System.out.println("and the length of the Encryped AES key is then put into its own file.");
                    System.out.println("To decrypt a file this process is reversed, the first 4 bytes of");
                    System.out.println("the encryped file are read as an intiger containing the length the");
                    System.out.println("encryped AES key. The computer then decrypts the encrypted AES key using");
                    System.out.println("the PGP private key. Using the decrypted AES key we finally decrypt the");
                    System.out.println("the encrypted message");
                    System.out.println("");
                    System.out.println("[enter anything to continue]");
                    scan.next();
                    System.out.println("For an exmaple of this select the run instruction option (6) and run the");
                    System.out.println("'Program.txt' file. This program generates the PGP keys (Public.key and Private.key)");
                    System.out.println("and go through the process of encrypting ( Encrypted.txt ) and decrypting");
                    System.out.println("(Decrpyted.txt) the Data.txt file");
                    System.out.println("");
                    System.out.println("[enter anything to continue]");
                    scan.next();
                    break;
                case 8 :
                    if (automatic) {
                        System.out.println("Ending automatic program");
                        automatic = false;
                        scan = new Scanner(System.in);
                        break;
                    }
                    System.out.println("Exiting program");
                    running = false;
                    break;
                case 9 :
                
            }
        }
        scan.close();
    }

    public static byte[] ReadFile(String Path) throws IOException {
        File file = new File(System.getProperty("user.dir") + "//" + Path);
        return Files.readAllBytes(file.toPath());
    }
    
    public static void WriteFile(String path,byte[] key) throws IOException{
    FileOutputStream out = new FileOutputStream(path);
    out.write(key);
    out.close();
    }
}