//A utility class that provides some functions for manipulation of bits in a 64-bit long
public class BitUtils {

    //converts a 64-bit long into a hexadecimal string with 16-characters
    public static String hex(long data){
        return String.format("0x%016X",data);
    }

    //get the value of bit pos of a word
    //note that pos==0 equals the least significant bit
    //observe that pos should be in the interval 0 <= pos <= 63
    public static long getBit(long data,int pos){
        //shift to get the bit at position pos as least significant bit
        //then output value of last bit
        long temp = data >>> pos;
        return temp & 1;
    }

    //set bit at position pos of a word to the value val
    //observe that val should be 0 or 1 and
    //pos should be in the interval 0 <= pos <= 63
    public static long setBit(long data,int pos,long val){
        //mask is a 64-bit word with only bit at position pos set to 1
        long mask = 1L<<pos;
        //System.out.println(hex(mask));
        if(val==1){
            //return data but with bit pos set to 1
            return data|mask;
        }
        if(val==0){
            //invert the bits of mask then return data with bit pos set to 0
            return data&(~mask);
        }
        return 0;
    }

}
