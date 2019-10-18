import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.BitSet;
import javafx.application.Application;
import javafx.scene.control.Alert;

//Java implementation of the cipher Present
//Note! to extract and set individual bits of a word you have been given BitUtils
public class Present {

    //the S-box in Present
    //private long[] SBox = {0xC,0x5,0x6,0xB,0x9,0x0,0xA,0xD,0x3,0xE,0xF,0x8,0x4,0x7,0x1,0x2};
    private BigInteger[] SBox = new BigInteger[] { BigInteger.valueOf(12),
            BigInteger.valueOf(5), BigInteger.valueOf(6), BigInteger.valueOf(11),
            BigInteger.valueOf(9), BigInteger.valueOf(0), BigInteger.valueOf(10),
            BigInteger.valueOf(13), BigInteger.valueOf(3), BigInteger.valueOf(14),
            BigInteger.valueOf(15), BigInteger.valueOf(8), BigInteger.valueOf(4),
            BigInteger.valueOf(7), BigInteger.valueOf(1), BigInteger.valueOf(2) };

    private static final int[] PBox = new int[] { 0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3,
            19, 35, 51, 4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55, 8, 24, 40, 56,
            9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59, 12, 28, 44, 60, 13, 29, 45, 61, 14, 30,
            46, 62, 15, 31, 47, 63 };

    private static final BigInteger[] SBox_inv = new BigInteger[] { BigInteger.valueOf(5),
            BigInteger.valueOf(14), BigInteger.valueOf(15), BigInteger.valueOf(8),
            BigInteger.valueOf(12), BigInteger.valueOf(1), BigInteger.valueOf(2),
            BigInteger.valueOf(13), BigInteger.valueOf(11), BigInteger.valueOf(4),
            BigInteger.valueOf(6), BigInteger.valueOf(3), BigInteger.valueOf(0),
            BigInteger.valueOf(7), BigInteger.valueOf(9), BigInteger.valueOf(10) };

    private static final int[] PBox_inv = new int[] { 0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44,
            48, 52, 56, 60, 1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 2, 6, 10,
            14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62, 3, 7, 11, 15, 19, 23, 27, 31, 35,
            39, 43, 47, 51, 55, 59, 63 };

    //an array that stores the 33 roundkeys
    //private long[] RoundKeys = new long[33];
    private BigInteger[] RoundKeys = new BigInteger[33];

    private static final BigInteger MASK4 = BigInteger.ONE.shiftLeft(4).subtract(BigInteger.ONE);

    //takes a 80-bit key and generates the corresponding round keys
    //keyH contains the 16-most significant bits of the key and keyL the 64 least significant
    public void initKey(long keyH, long keyL){
        //store the key in a 80-bit register (implemented as an array of 2 long)
        //store the 64 least significant bits in keyReg[0] and the 16 most significant bits in keyReg[1]
        System.out.println("Initiating key"); //remove after testing
        long[] keyReg = new long[2];
        keyReg[0] = keyL;//Least sig (64)
        keyReg[1] = keyH;//Most sig (16)
        /**Exp*/
        //System.out.println(keyH+"");
        //        System.out.println(Arrays.toString(keyReg));
        //        System.out.println(new BigInteger("88", 16).toString(2));
//        BigInteger key;
//        key = BigInteger.valueOf(keyReg[0]);
        String wholekey = "00000000000000000000";
        BigInteger key =  new BigInteger(wholekey, 16);



        //System.out.println(key.toString(2));//To Binary
        BigInteger mask19 = BigInteger.ONE.shiftLeft(19).subtract(BigInteger.ONE);
        BigInteger mask76 = BigInteger.ONE.shiftLeft(76).subtract(BigInteger.ONE);

        //repeat 33 times (note start with iteration counter i = 1)
        for(int i=1;i<=32;i++){
            //extract the 64-most significant bits and store them in RoundKeys[i]
            //addRoundKey(blockBitSet, keys[i]);
            RoundKeys[i] = key.shiftRight(16);
            //System.out.println(key.shiftRight(16).toString(16));

            //rotate the bits of the key 61 bit positions to the left (or equivalently 19 bit positions to the right)
            key = key.and(mask19).shiftLeft(61).add(key.shiftRight(19));

            //Apply the S-box to the 4 most significant bits
            key = SBox[key.shiftRight(76).intValue()].shiftLeft(76).add(key.and(mask76));

            //xor with the round counter i
            key = key.xor(BigInteger.valueOf(i).shiftLeft(15));
        }

//        System.out.println(Arrays.toString(RoundKeys));
    }

    //decrypt a block of 64-bit plaintext
    //before decryption you need to initiate with key
//    public long decrypt(long ciphertext){
//        long plaintext = 0;
//        System.out.println("Decryption"); //remove after testing
//        return plaintext;
//    }
    public long decrypt(long toDecrypt) {
        BigInteger cipher;
        cipher = BigInteger.valueOf(toDecrypt);
        //System.out.println(Arrays.toString(RoundKeys));
        System.out.println(RoundKeys[32]);

        BigInteger state = cipher;
//        for (int i = 0; i < rounds - 1; i++) {
        for (int i = 1; i < 31; i++) {
//            System.out.println(i);
//            System.out.println(RoundKeys[32 - i]);
            state = addRoundKey(state, RoundKeys[31 - i]);
            state = pLayer_dec(state);
            state = sBoxLayer_dec(state);
        }

        return addRoundKey(state, RoundKeys[1]).longValue();
    }

    private BigInteger pLayer_dec(BigInteger state) {
        BigInteger output = BigInteger.ZERO;
        for (int i = 0; i < 64; i++) {
            if (state.testBit(i)) {
                output = output.setBit(PBox_inv[i]);
            }
        }
        return output;
    }

    private BigInteger sBoxLayer_dec(BigInteger state) {
        BigInteger output = BigInteger.ZERO;
        for (int i = 0; i < 16; i++) {
            output = output.add(SBox_inv[state.shiftRight(i * 4).and(MASK4).intValue()]
                    .shiftLeft(i * 4));
        }
        return output;
    }

    //performs the SBox operations on all 64-bits of a word
    private BigInteger sBoxLayer(BigInteger state) {
        BigInteger output = BigInteger.ZERO;
        for (int i = 0; i < 16; i++) {
            output = output.add(SBox[state.shiftRight(i * 4).and(MASK4).intValue()]
                    .shiftLeft(i * 4));
        }
        return output;
    }

    //performs the permutation layer of Present
    private BigInteger pLayer(BigInteger state) {
        BigInteger output = BigInteger.ZERO;
        for (int i = 0; i < 64; i++) {
            if (state.testBit(i)) {
                output = output.setBit(PBox[i]);
            }
        }
        return output;
    }

    //Encrypt
    public Long encrypt(long  toEncrypt) {
        //Call initKeys() to populate roundkeys
        BigInteger message;
        message = BigInteger.valueOf(toEncrypt);

        BigInteger state = message;
        //for (int i = 0; i < rounds-1; i++) {
        for (int i = 1; i <= 31; i++) {
            state = addRoundKey(state, RoundKeys[i]);
            state = sBoxLayer(state);
            state = pLayer(state);
        }
        return addRoundKey(state, RoundKeys[32]).longValue();
    }

    private BigInteger addRoundKey(BigInteger state, BigInteger roundKey) {
        return state.xor(roundKey);
    }

}
