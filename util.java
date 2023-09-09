
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * 
 * Utility class to service Main & Keccak
 * Lots of byte array operations
 * Custom serialization of the Point object as Zip and Unzip 
 * 
 * @authors Lindsay Ding, Alan Thompson, Christopher Henderson
 *
 */
public class util {
	
	public static final Point BIG_TEST_POINT() {
		return new Point(Point.p.multiply(BigInteger.valueOf((long)(Math.random() * 23711))), Point.r.multiply(BigInteger.valueOf((long)(Math.random() * 11732))));
	}
	
	public static final Point MED_TEST_POINT() {
		BigInteger beefCake = new BigInteger("905324637344786785227");
		return new Point(BigInteger.valueOf((long)(Math.random() * 1946366711)).multiply(beefCake), BigInteger.valueOf((long)(Math.random() * 1815145732)).multiply(beefCake));
	}
	
	public static final Point SMALL_TEST_POINT() {
		return new Point(BigInteger.valueOf((long)(Math.random() * 23711)), BigInteger.valueOf((long)(Math.random() * 11732)));
	}
	
	public static final Point ASYM_TEST_POINT() {
		return new Point(Point.p.multiply(BigInteger.valueOf((long)(Math.random() * 2371))), BigInteger.valueOf((long)(Math.random() * 11732)));
	}
	
//	public static final String 
//		FILE_NOT_FOUND = "|=> That file could not be located or does not exist!",
//		FILE_NOT_ENCRYPTED = "|=> That file is not encrypted or is otherwise incompatible!";
	
	/**
	 * Compute the scalar multiplication of the point G on the curve by the scalar s.
	 * Reference: Elliptic Curve slides - "Exponentiation" algorithm (Elliptic curve version)
	 * @param G a point on the curve
	 * @param s the scalar factor
	 * @return the result of s * G
	 */
    public static Point pointMultiplyByScalar(Point G, BigInteger s) {
        if (s.equals(BigInteger.ZERO)) return new Point();

        if (s.signum() == -1) {
            s = s.negate();
            G = G.opposite();
        }

        String binaryS = s.toString(2);
        Point P = G;
        if (binaryS.length() == 1) return P;
        for (int i = 1; i < binaryS.length(); i++) {
            P = P.sum(P);
            if (binaryS.charAt(i) == '1') {
                P = P.sum(G);
            }
        }
        return P;
    }
    
    /**
     * 
     * First 8 bytes record the length of the X cord and Y cord,
	 * X length are in bytes [0,4), Y length [4,8)
	 * from [8, 8+X length) are the bytes for the X cord
	 * then [8+X length, 8+X length + Y length)
	 * 8+X length + Y length should equal pointData.length
     * 
     *  [xLen][yLen][   X   ][   Y   ]  <- Array
     *   4-B   4-B   xLen-B   yLen-B    <- Bytes
     * @param pt The Point
     * @return Byte array of the Point data
     */
	public static byte[] pointDataZip(final Point pt) {
		byte[] xBytes = pt.getXBytes();
		byte[] yBytes = pt.getYBytes();

		byte[] xBytesLength = numberToByteArray(xBytes.length);
		byte[] yBytesLength = numberToByteArray(yBytes.length);

		return concatBytes(xBytesLength, yBytesLength, xBytes, yBytes);
	}
	
	public static Point pointDataUnzip(byte[] pointData) {
		try {
			int[] lengths = readZipedPointInfo(pointData);
			int xLen = lengths[0], yLen = lengths[1];
			
			int xBytesStart = 8;
			int yBytesStart = xBytesStart + xLen;
			int theEnd = yBytesStart + yLen;
	
			byte[] xBytes = Arrays.copyOfRange(pointData, xBytesStart, yBytesStart);
			byte[] yBytes = Arrays.copyOfRange(pointData, yBytesStart, theEnd);
			
			return new Point(new BigInteger(xBytes),new BigInteger(yBytes));
		} catch(Exception e) { return null;}
	}
	
	/**
	 * First 8 bytes record the length of the X cord and Y cord,
	 * X length are in bytes [0,4), Y length [4,8)
	 * @param pointData
	 * @return int[] {X length, Y length}
	 */
	public static int[] readZipedPointInfo(byte[] pointData) throws ArrayIndexOutOfBoundsException {
		byte[] xByteLength = Arrays.copyOfRange(pointData, 0, 4);
		byte[] yByteLength = Arrays.copyOfRange(pointData, 4, 8);
		return new int[] {bytesToInt(xByteLength), bytesToInt(yByteLength)};
	}

	
	public static byte[] readByteData(final String path) {
		byte[] theBytes = null;
		
		try {theBytes = Files.readAllBytes(Paths.get(path));}
		catch (Exception easy) {System.out.println(Main.FILE_NOT_FOUND);}
		return theBytes;
	}
	
	public static void writeByteData(final String path, final byte[] theBytes) {
		try (FileOutputStream fos = new FileOutputStream(path)) {
			   fos.write(theBytes);
			} catch (IOException e) {
				e.printStackTrace();
			}
	}
	
	/**
	 * Unpacks a Elliptic-Point Cryptogram into its component parts
	 * @param theGram
	 * @return {Z, T, C}
	 */
	public static byte[][] ellipticCryptogramOpener(byte[] theGram) {
//		if (theGram.length < 72) return null;
		byte[] z,t,c;
		try {
			int[] pointLen = readZipedPointInfo(theGram);
			int zLen = 8 + pointLen[0] + pointLen[1];
			
			int
				z_srt =     0,  z_end = zLen,
				t_srt = z_end,  t_end = t_srt + 64,
				c_srt = t_end,  c_end = theGram.length;
			
			
			
			
			z = Arrays.copyOfRange(theGram, z_srt, z_end);
			t = Arrays.copyOfRange(theGram, t_srt, t_end);
			c = Arrays.copyOfRange(theGram, c_srt, c_end);
		}
		catch(Exception e) {
			System.out.println(Main.FILE_NOT_ENCRYPTED);
			return null;
		}

		return new byte[][] {z, t, c};
	}
	
	/**
	 * Unpacks a Symmetric Cryptogram into its component parts
	 * @param theGram
	 * @return {Z, T, C}
	 */
	public static byte[][] symmetricCryptogramOpener(byte[] theGram) {
		int
			z_srt =     0,  z_end = 64,
			t_srt = z_end,  t_end = t_srt + 64,
			c_srt = t_end,  c_end = theGram.length;
		
		byte[] z = Arrays.copyOfRange(theGram, z_srt, z_end);
		byte[] t = Arrays.copyOfRange(theGram, t_srt, t_end);
		byte[] c = Arrays.copyOfRange(theGram, c_srt, c_end);
		
		return new byte[][] {z, t, c};
	}
		
	public static byte[] concatBytes(byte[] a, byte[] b) {
		byte[] cat = new byte[a.length+b.length];
		int j = 0;
		for (int i = 0; i < a.length; i++) {
			cat[j++] = a[i];
		}
		for (int i = 0; i <  b.length; i++) {
			cat[j++] = b[i];
		}
		
		return cat;
	}
	
	public static byte[] concatBytes(byte[] a, byte[]... moreBytes) {
		byte[] cat = a;
		
		for (byte[] bark : moreBytes) {
			byte[] dog = concatBytes(cat, bark);
			cat = dog;
		}
		return cat;
	}
	
	public static byte[] xorBytes(byte[] a, byte[] b) {
		assert a.length == b.length;
		byte[] xor = new byte[a.length];
		for (int i = 0; i < a.length; i++) {
			xor[i] = (byte) (a[i] ^ b[i]);
		}
		
		return xor;
	}
	
    /**
     * Convert a byte array to its corresponding big integer value
     * @param arr byte array (from kmacxof256)
     * @return negative, zero or positive value in big integer
     */
    public static BigInteger bytesToBigInt(byte[] arr) {
        boolean isZero = true;
        for (byte b : arr) {
            if (b != 0) {
                isZero = false;
                break;
            }
        }
        if (isZero) return BigInteger.ZERO;
        int sign = ((arr[0] & 0x80) == 0 ? 1 : -1);
        return new BigInteger(sign, arr);
    }
    
    // Adapted From: https://stackoverflow.com/questions/2183240/java-integer-to-byte-array
	public static byte[] numberToByteArray(int number) {
		byte[] theBytes = {
            (byte)((number >>> 24) & 0xff),
            (byte)((number >>> 16) & 0xff),
            (byte)((number >>> 8) & 0xff),
            (byte)( number & 0xff)
          };
		return theBytes;
	}
	
	// Adapted From: https://www.baeldung.com/java-byte-array-to-number
	public static int bytesToInt(byte[] theBytes) {
		if (theBytes.length != 4) {
			System.err.println("Invalid size of byte array");
			return 0;
		}
		
		int number = 0;
		for (byte b : theBytes) {
			number = (number << 8) + (b & 0xFF);
		}
		
		return number;
	}
	
	public static long bytesToLong(byte[] state, int startIndex) {
		long l = 0;
		for (int i = startIndex; i < startIndex + 8; i++) {
			l <<= 8; // shift by 8 bits -> total 64
			l |= (long) (state[i] & 0xFF); // only take the last 8 bits each time
		}
		return l;
	}

	public static byte[] longToBytes(long val) {
		byte[] bytes = new byte[8];
		for (int i = 0; i < 8; i++) {
			bytes[7 - i] = (byte) ((val >> (i * 8)) & 0xFF);
		}
		return bytes;
	}


	public static String bytesToHexString(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		int count = 0;
		for (int i = 0; i < bytes.length; i++) {
			sb.append(HexFormat.of().toHexDigits(bytes[i])).append(" ");
			count++;
			if (count > 7) {
				sb.append('\n');
				count = 0;
			}
		}
		return (sb.toString().toUpperCase());
	}
	
	public static String bytesToHexStringSimple(byte[] bytes) {
		String str = "";
		for (int i = 0; i < bytes.length; i++)
			str += (HexFormat.of().toHexDigits(bytes[i]))+" ";
		return str;
	}
    
}
