import java.math.BigInteger;

public class PresentMain {
    static Present cipher = new Present();
    public static void main(String[] args){
        //run the test vectors for Present

//        //key = 0000 0000000000000000
//        //plaintext = 0000000000000000
//        //the ciphertext should be 6679c1387b228445
//        cipher.initKey(0x0L,0x0L);
//        long plaintext = 0x0L;
//        long ciphertext = cipher.encrypt(plaintext);
//        System.out.println(BitUtils.hex(ciphertext));
//        //key = ffff ffffffffffffffff
//        //plaintext = 0000000000000000
//        //the ciphertext should be e72c46c0f5945049
//        cipher.initKey(0xFFFFL,0xFFFFFFFFFFFFFFFFL);
//        plaintext = 0x0L;
//        ciphertext = cipher.encrypt(plaintext);
//        System.out.println(BitUtils.hex(ciphertext));
//        System.out.println(ciphertext);
//        //key = 0000 0000000000000000
//        //plaintext = FFFFFFFFFFFFFFFF
//        //the ciphertext should be a112ffc72f68417b
//        cipher.initKey(0x0L,0x0L);
//        plaintext = 0xFFFFFFFFFFFFFFFFL;
//        ciphertext = cipher.encrypt(plaintext);
//        System.out.println(BitUtils.hex(ciphertext));


        //Encryptions
        runEBC_Encrypt(1000);
        runEBC_Encrypt(10000);
        runEBC_Encrypt(100000);

        runCBC_Encrypt(1000);
        runCBC_Encrypt(10000);
        runCBC_Encrypt(100000);

        runCTR_Encrypt(1000);
        runCTR_Encrypt(10000);
        runCTR_Encrypt(100000);

        //Decryptions
        runEBC_Decrypt(1000);
        runEBC_Decrypt(10000);
        runEBC_Decrypt(100000);

        runCBC_Decrypt(1000);
        runCBC_Decrypt(10000);
        runCBC_Decrypt(100000);

        runCTR_Decrypt(1000);
        runCTR_Decrypt(10000);
        runCTR_Decrypt(100000);

    }

    public static void runEBC_Encrypt (int bits){
        //Generate Key
        String key = cipher.generateRandomBits(80);

        //Generate State (1kb, 10kb or 100kb)
        String state = cipher.generateRandomBits(bits);

        //Start timer
        cipher.startTimer();

        //Generate Round Keys
        cipher.initKey(new BigInteger(key.substring(0,4), 16).longValue(),new BigInteger(key.substring(4), 16).longValue());

        //Encrypt the plain text using ECB to get cipher text
        String encryptedtext = cipher.encryptLongState_ECB(state);
        //System.out.println("Cipher Text:  " + encryptedtext);

        //Stop Timer and display how long it took
        Long elapsedTime = cipher.stopTimer();
        System.out.println("Time to encrypt using ECB (Milliseconds): " + elapsedTime);

    }

    public static void runCBC_Encrypt (int bits) {
        //Generate Key
        String key = cipher.generateRandomBits(80);

        //Generate State (1kb, 10kb or 100kb)
        String state = cipher.generateRandomBits(bits);

        //Start timer
        cipher.startTimer();

        //Generate Round Keys
        cipher.initKey(new BigInteger(key.substring(0,4), 16).longValue(),new BigInteger(key.substring(4), 16).longValue());

        //Encrypt the plain text using CBC to get cipher text
        String encryptedtext = cipher.encryptLongState_CBC(state);
        //System.out.println("Cipher Text:  " + encryptedtext);

        //Stop Timer and display how long it took
        Long elapsedTime = cipher.stopTimer();
        System.out.println("Time to encrypt using CBC (Milliseconds): " + elapsedTime);

    }

    public static void runCTR_Encrypt (int bits){
        //Generate Key
        String key = cipher.generateRandomBits(80);

        //Generate State (1kb, 10kb or 100kb)
        String state = cipher.generateRandomBits(bits);

        //Start timer
        cipher.startTimer();

        //Generate Round Keys
        cipher.initKey(new BigInteger(key.substring(0,4), 16).longValue(),new BigInteger(key.substring(4), 16).longValue());

        //Encrypt the plain text using CTR to get cipher text
        String encryptedtext = cipher.encryptLongState_CTR(state);
        //System.out.println("Cipher Text:  " + encryptedtext);


        //Stop Timer and display how long it took
        Long elapsedTime = cipher.stopTimer();
        System.out.println("Time to encrypt using CTR (Milliseconds): " + elapsedTime);

    }

    public static void runEBC_Decrypt (int bits){
        //Generate Key
        String key = cipher.generateRandomBits(80);

        //Generate State (1kb, 10kb or 100kb)
        String cipherMsg = cipher.generateRandomBits(bits);

        //Start timer
        cipher.startTimer();

        //Generate Round Keys
        cipher.initKey(new BigInteger(key.substring(0,4), 16).longValue(),new BigInteger(key.substring(4), 16).longValue());

        //Decrypt the plain text using ECB to get original text
        String decryptedtext = cipher.decryptLongCipher_ECB(cipherMsg);
        //System.out.println("Original Text:  " + decryptedtext);

        //Stop Timer and display how long it took
        Long elapsedTime = cipher.stopTimer();
        System.out.println("Time to decrypt using ECB (Milliseconds): " + elapsedTime);

    }

    public static void runCBC_Decrypt (int bits){
        //Generate Key
        String key = cipher.generateRandomBits(80);

        //Generate State (1kb, 10kb or 100kb)
        String cipherMsg = cipher.generateRandomBits(bits);

        //Start timer
        cipher.startTimer();

        //Generate Round Keys
        cipher.initKey(new BigInteger(key.substring(0,4), 16).longValue(),new BigInteger(key.substring(4), 16).longValue());

        //Decrypt the plain text using ECB to get original text
        String decryptedtext = cipher.decryptLongCipher_CBC(cipherMsg);
        //System.out.println("Original Text:  " + decryptedtext);

        //Stop Timer and display how long it took
        Long elapsedTime = cipher.stopTimer();
        System.out.println("Time to decrypt using CBC (Milliseconds): " + elapsedTime);

    }

    public static void runCTR_Decrypt (int bits){
        //Generate Key
        String key = cipher.generateRandomBits(80);

        //Generate State (1kb, 10kb or 100kb)
        String cipherMsg = cipher.generateRandomBits(bits);

        //Start timer
        cipher.startTimer();

        //Generate Round Keys
        cipher.initKey(new BigInteger(key.substring(0,4), 16).longValue(),new BigInteger(key.substring(4), 16).longValue());

        //Decrypt the plain text using ECB to get original text
        String decryptedtext = cipher.decryptLongCipher_CTR(cipherMsg);
        //System.out.println("Original Text:  " + decryptedtext);

        //Stop Timer and display how long it took
        Long elapsedTime = cipher.stopTimer();
        System.out.println("Time to decrypt using CTR (Milliseconds): " + elapsedTime);

    }


}