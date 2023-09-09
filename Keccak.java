
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;


/**
 * 
 * SHA-3 Keccak Cryptogram Project
 * 
 * Heavily inspired from Markku-Juhani O. Saarinen's C implementation: <https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c>
 * 
 * @authors Lindsay Ding, Alan Thompson, Christopher Henderson
 *
 */
public class Keccak {

	final static int KECCAKF_ROUNDS = 24;
	final static boolean BYTE_ORDER_LITTLE_ENDIAN = true;

	public static class sha3_ctx_t {
		public class struct_st {
			byte[] b = new byte[200];
		}
		struct_st st = new struct_st();
		int pt, rsiz, mdlen;
	};

	// ROTL64 MACRO
	public static long ROTL64(long x, int y) {
		return (x << y) | (x >>> (64 - (y)));
	}

	public static void sha3_keccakf(byte[] byteSt) {

		long[] st = new long[25];
		int index = 0;
		for (int i = 0; i < st.length; i++) {
			st[i] = util.bytesToLong(byteSt, index);
			index += 8;
		}

		// constants
		final long[] keccakf_rndc = { 0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
				0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
				0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL, 0x000000008000808bL,
				0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
				0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L,
				0x8000000080008008L };

		final int[] keccakf_rotc = { 1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61,
				20, 44 };
		final int[] keccakf_piln = { 10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6,
				1 };

		// variables
		int i, j, r;
		long t;
		long[] bc = new long[5];

		if (BYTE_ORDER_LITTLE_ENDIAN) {
			byte[] v;
			// endianess conversion. this is redundant on little-endian targets
			for (i = 0; i < 25; i++) {
				v = util.longToBytes(st[i]);
				st[i] = (((long) v[0]) & 0xFF) | ((((long) v[1]) & 0xFF) << 8) | ((((long) v[2]) & 0xFF) << 16)
						| ((((long) v[3]) & 0xFF) << 24) | ((((long) v[4]) & 0xFF) << 32)
						| ((((long) v[5]) & 0xFF) << 40) | ((((long) v[6]) & 0xFF) << 48)
						| ((((long) v[7]) & 0xFF) << 56);
			}
		}

		// actual iteration
		for (r = 0; r < KECCAKF_ROUNDS; r++) {

			// System.out.println("Before" + Arrays.toString(st));
			// new Scanner(System.in).nextLine();
			// Theta
			for (i = 0; i < 5; i++)
				bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

			for (i = 0; i < 5; i++) {
				t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
				for (j = 0; j < 25; j += 5)
					st[j + i] ^= t;
			}

			// System.out.println("Theta" + Arrays.toString(st));
			// new Scanner(System.in).nextLine();

			// Rho Pi
			t = st[1];
			for (i = 0; i < 24; i++) {
				j = keccakf_piln[i];
				bc[0] = st[j];
				st[j] = ROTL64(t, keccakf_rotc[i]);
				t = bc[0];
			}

			// Chi
			for (j = 0; j < 25; j += 5) {
				for (i = 0; i < 5; i++)
					bc[i] = st[j + i];
				for (i = 0; i < 5; i++)
					st[j + i] ^= ((~bc[(i + 1) % 5]) & bc[(i + 2) % 5]);
			}

			// Iota
			st[0] ^= keccakf_rndc[r];
		}

		if (BYTE_ORDER_LITTLE_ENDIAN) {
			byte[] v;
			// endianess conversion. this is redundant on little-endian targets
			for (i = 0; i < 25; i++) {
				v = util.longToBytes(st[i]);
				st[i] = (((long) v[0]) & 0xFF) | ((((long) v[1]) & 0xFF) << 8) | ((((long) v[2]) & 0xFF) << 16)
						| ((((long) v[3]) & 0xFF) << 24) | ((((long) v[4]) & 0xFF) << 32)
						| ((((long) v[5]) & 0xFF) << 40) | ((((long) v[6]) & 0xFF) << 48)
						| ((((long) v[7]) & 0xFF) << 56);
			}
		}

		int idx = 0;
		for (int n = 0; n < st.length; n++) {
			byte[] temp = util.longToBytes(st[n]);
			System.arraycopy(temp, 0, byteSt, idx, 8);
			idx += 8;
		}
	}

	private static void sha3_init(sha3_ctx_t c, int mdlen) {
		for (int i = 0; i < 200; i++)
			c.st.b[i] = 0;
		c.mdlen = mdlen;
		c.rsiz = 200 - 2 * mdlen;
		c.pt = 0;
	}

	private static void sha3_update(sha3_ctx_t c, byte[] data, int len) {
		int j = c.pt;
		for (int i = 0; i < len; i++) {
			c.st.b[j++] ^= data[i];
			if (j >= c.rsiz) {
				sha3_keccakf(c.st.b);
				j = 0;
			}
		}
		c.pt = j;
	}

	private static void shake_xof(sha3_ctx_t c, boolean flag) {
		// true -> cShake | false -> shake
		c.st.b[c.pt] ^= (byte) (flag ? 0x04 : 0x1F);
		c.st.b[c.rsiz - 1] ^= 0x80;
		sha3_keccakf(c.st.b);
		c.pt = 0;
	}

	private static void shake_out(sha3_ctx_t c, byte[] out, int len) {
		int i;
		int j = c.pt;
		for (i = 0; i < len; i++) {
			if (j >= c.rsiz) {
				sha3_keccakf(c.st.b);
				j = 0;
			}
			out[i] = c.st.b[j++];
		}

		c.pt = j;
	}

	public static byte[] KMACXOF256(byte[] K, byte[] X, int L, byte[] S) {
		byte[] paddedK = bytepad(encode_string(K), 136);
		byte[] encodedX = new byte[paddedK.length + X.length + 2];
		System.arraycopy(paddedK, 0, encodedX, 0, paddedK.length);
		System.arraycopy(X, 0, encodedX, paddedK.length, X.length);
		System.arraycopy(right_encode(BigInteger.ZERO), 0, encodedX, encodedX.length - 2, 2);
		return cSHAKE256(encodedX, L, "KMAC", S);
	}

	private static byte[] cSHAKE256(byte[] X, int L, String N, byte[] S) {
		if (N.length() == 0 && S.length == 0)
			return SHAKE256(X, L);
		byte[] encodedN = encode_string(N.getBytes(StandardCharsets.US_ASCII));
		byte[] encodedS = encode_string(S);
		byte[] combineNS = new byte[encodedN.length + encodedS.length];
		System.arraycopy(encodedN, 0, combineNS, 0, encodedN.length);
		System.arraycopy(encodedS, 0, combineNS, encodedN.length, encodedS.length);
		byte[] paddedNS = bytepad(combineNS, 136);
		byte[] res = new byte[paddedNS.length + X.length];
		System.arraycopy(paddedNS, 0, res, 0, paddedNS.length);
		System.arraycopy(X, 0, res, paddedNS.length, X.length);
		return sponge(res, L, true);

	}

	private static byte[] SHAKE256(byte[] M, int d) {
		byte[] res = new byte[M.length];
		System.arraycopy(M, 0, res, 0, M.length);
		return sponge(res, d, false);
	}

	private static byte[] sponge(byte[] data, int d, boolean flag) {
		int byteLength = d / 8;
		byte[] output = new byte[byteLength];
		sha3_ctx_t sha3 = new sha3_ctx_t();
		sha3_init(sha3, 32);
		sha3_update(sha3, data, data.length);
		shake_xof(sha3, flag);
		shake_out(sha3, output, byteLength);

		return output;
	}

	private static byte[] bytepad(byte[] X, int w) {
		assert w > 0;
		BigInteger bigInt = BigInteger.valueOf(w);
		byte[] wenc = left_encode(bigInt);
		byte[] z = new byte[w * ((wenc.length + X.length + w - 1) / w)];
		System.arraycopy(wenc, 0, z, 0, wenc.length);
		System.arraycopy(X, 0, z, wenc.length, X.length);
		for (int i = wenc.length + X.length; i < z.length; i++) {
			z[i] = (byte) 0;
		}
		return z;
	}

	private static byte[] right_encode(BigInteger x) {
		// assert x.signum() > 0; // 2^2040
		if (x.equals(BigInteger.ZERO))
			return new byte[] { 0, 1 };
		byte[] byteArr = x.toByteArray();
		int n = 1;
		BigInteger bound = new BigInteger("256");
		while (x.compareTo(bound) >= 0) {
			n++;
			bound = BigInteger.TWO.pow(n * 8);
		}
		if (byteArr[0] == 0) {
			byte[] arr = new byte[byteArr.length - 1];
			System.arraycopy(byteArr, 1, arr, 0, arr.length);
			byteArr = arr;
		}
		byte[] res = new byte[byteArr.length + 1];
		res[res.length - 1] = (byte) n;
		for (int i = 0; i < byteArr.length; i++) {
			res[i] = (byte) (byteArr[i] & 0xFF);
		}
		return res;

	}

	private static byte[] left_encode(BigInteger x) {
		// assert x.signum() > 0; // 2^2040
		if (x.equals(BigInteger.ZERO))
			return new byte[] { 1, 0 };
		byte[] byteArr = x.toByteArray();
		int n = 1;
		BigInteger bound = new BigInteger("256");
		while (x.compareTo(bound) >= 0) {
			n++;
			bound = BigInteger.TWO.pow(n * 8);
		}

		if (byteArr[0] == 0) {
			byte[] arr = new byte[byteArr.length - 1];
			System.arraycopy(byteArr, 1, arr, 0, arr.length);
			byteArr = arr;
		}
		byte[] res = new byte[byteArr.length + 1];
		res[0] = (byte) n;
		for (int i = 0; i < byteArr.length; i++) {
			res[i + 1] = (byte) (byteArr[i] & 0xFF);
		}
		return res;
	}

	private static byte[] encode_string(byte[] s) {
		byte[] len = left_encode(BigInteger.valueOf((s.length * 8)));
		byte[] res = new byte[len.length + s.length];
		System.arraycopy(len, 0, res, 0, len.length);
		System.arraycopy(s, 0, res, len.length, s.length);
		return res;
	}

}
