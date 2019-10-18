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
    private long[] SBox = {0xC,0x5,0x6,0xB,0x9,0x0,0xA,0xD,0x3,0xE,0xF,0x8,0x4,0x7,0x1,0x2};

    //an array that stores the 33 roundkeys
    private long[] RoundKeys = new long[33];

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
        //        System.out.println(Arrays.toString(keyReg));
        //        System.out.println(new BigInteger("88", 16).toString(2));
        String wholekey = "00000000000000000000";
        BigInteger key =  new BigInteger(wholekey, 16);
        //System.out.println(key.toString(2));//To Binary

        //repeat 33 times (note start with iteration counter i = 1)
        for(int i=1;i<=32;i++){
            //extract the 64-most significant bits and store them in RoundKeys[i]
            //addRoundKey(blockBitSet, keys[i]);
            RoundKeys[i] = key.shiftRight(16).intValue();
            System.out.println(key.shiftRight(16).toString(16));

            //rotate the bits of the key 61 bit positions to the left (or equivalently 19 bit positions to the right)

            BigInteger shift = key.and(new BigDecimal(Math.pow(2, 19) - 1).toBigInteger());
            key = shift.shiftLeft(61).add(key.shiftRight(19));

            key = SBox[key.shiftRight(76).intValue()].shiftLeft(76).add(key.and(mask76));

            //Apply the S-box to the 4 most significant bits
            BigInteger bi1 = BigInteger.valueOf(SBox[key.shiftRight(76).intValue()]).shiftLeft(76);
            BigInteger pow = new BigDecimal(2).pow(76).toBigInteger();
            BigInteger bi2 = key.add(pow);



            //xor with the round counter i
            key = bi1.add(bi2);
            key = key.xor(BigInteger.valueOf(i).shiftLeft(15));

        }
    }

    private long rotateKeys(long key){



        return key;
    }

    private void addRoundKey(BitSet blockBitSet, long key) {
        BitSet keyBits =  convertToBitset(nuconvert(convertToBitset(key)));
        blockBitSet.xor(keyBits);
    }

    public static int nuconvert(BitSet bits) {
        int value = 0;
        for (int i = 0; i < bits.length(); ++i) {
            value += bits.get(i) ? (1 << i) : 0;
        }
        return value;
    }

    public static BitSet convertToBitset(long value) {
        BitSet bits = new BitSet();
        int index = 0;
        while (value != 0L) {
            if (value % 2L != 0) {
                bits.set(index);
            }
            ++index;
            value = value >>> 1;
        }
        return bits;
    }

    public static long convertToLong(BitSet bits) {
        long value = 0L;
        for (int i = 0; i < bits.length(); ++i) {
            value += bits.get(i) ? (1L << i) : 0L;
        }
        return value;
    }
/*Here*/
    //encrypt a block of 64-bit plaintext
    //before encryption you need to initiate with key
    public long encrypt(long plaintext){
        long ciphertext = 0;
        System.out.println("Encryption"); //remove after testing
        return ciphertext;
    }

    //decrypt a block of 64-bit plaintext
    //before decryption you need to initiate with key
    public long decrypt(long ciphertext){
        long plaintext = 0;
        System.out.println("Decryption"); //remove after testing
        return plaintext;
    }

    //performs the SBox operations on all 64-bits of a word
    private long sBoxLayer(long state){
        //split the 64-bit state into 16 blocks with 4-bits each
        //for each 4-bit block apply the S-box
        //combine all 16 4-bit blocks from the S-box into a new 64-bit state
        long newState = 0L;
        System.out.println("S-Box"); //remove after testing
        return newState;
    }

    //performs the permutation layer of Present
    private long pLayer(long state){
        //for each bit i of the state do the following
        //find the value of i
        //store the value of i in position P(i) in newState
        //P(i) is given as P(i) = i*16 mod 63, 0<= i < 63
        //P(i) = i, i = 63
        long newState = 0L;
        System.out.println("P layer"); //remove after testing
        return newState;
    }
}
