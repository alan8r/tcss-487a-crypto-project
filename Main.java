
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

/**
 * 
 * SHA-3 Keccak Cryptogram Project
 * 
 *** FOR PART 1:
 * 		Heavily inspired from Markku-Juhani O. Saarinen's C implementation: 
 * 		<https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c>
 * 
 *** FOR PART 2:
 * 	TCSS 487 PJ2 instructions 
 * 
 * 
 * @authors Lindsay Ding, Alan Thompson, Christopher Henderson
 *
 */
public class Main {
	private static Scanner scan_man;
	private static boolean running;
	private static int currOpp;

	private static void opt1_FileHash() {
		System.out.println(FILE_NOTES);
		byte[] m = loadFile("hash");
		byte[] out = Keccak.KMACXOF256($NULL, m, 512, $D);
		
		printOutput(out);
	}
	
	private static void opt2_ConsoleHash() {
		String input = getConsoleString(CONSOLE_GET);
		byte[] m = input.getBytes();
		byte[] out = Keccak.KMACXOF256($NULL, m, 512, $D);
		
		printOutput(out);
	}
	
	private static void opt3_FileMAC() {
		System.out.println(FILE_NOTES);
		String passPhrase = getConsoleString(PASSPHRASE);
		byte[] m = loadFile("generate a MAC for");
		byte[] pw = passPhrase.getBytes();
		byte[] out = Keccak.KMACXOF256(pw, m, 512, $T); // outputs a 512-bit string
		
		printOutput(out);
	}
	
	private static void opt4_ConsoleMAC() {
		String input = getConsoleString(CONSOLE_GET + "MAC: ");
		String passPhrase = getConsoleString(PASSPHRASE);
		byte[] m = input.getBytes();
		byte[] pw = passPhrase.getBytes();
		byte[] out = Keccak.KMACXOF256(pw, m, 512, $T); // outputs a 512-bit string
		
		printOutput(out);
	}
	
	private static void opt5_EncryptFile() {
		System.out.println(FILE_NOTES);
		byte[] m = loadFile("encrypt");
		String passPhrase = getConsoleString(PASSPHRASE);
		String saveAsFile = getUserFileName("encrypted", "save");
		
		byte[] pw = passPhrase.getBytes();
		
		int byteLen = 512 / 8;
		
		SecureRandom random = new SecureRandom();
		byte[] z = new byte[byteLen];
		random.nextBytes(z);
		
		byte[] z_pw = util.concatBytes(z, pw);
		
		byte[] ke_ka = Keccak.KMACXOF256(z_pw, $NULL, 1024, $S);
		byte[] ke = Arrays.copyOfRange(ke_ka, 0, byteLen/2);
		byte[] ka = Arrays.copyOfRange(ke_ka, byteLen/2, byteLen);
		
		byte[] c_pre = Keccak.KMACXOF256(ke, $NULL, m.length * 8, $SKE);
		
		byte[] c = util.xorBytes(c_pre, m);
		
		byte[] t = Keccak.KMACXOF256(ka, m, 512, $SKA);
		
		byte[] Cryptogram = util.concatBytes(z,t,c);
		
		util.writeByteData(saveAsFile, Cryptogram);
	}
	
	private static void opt6_DecryptFile() {
		System.out.println(FILE_NOTES);
		byte[] decryptFile = loadFile("encrypted", "load");
		String passPhrase = getConsoleString(PASSPHRASE);
		String saveAsFile = getUserFileName("decrypted", "save");
		
		
		byte[][] cryptGrams = util.symmetricCryptogramOpener(decryptFile);
		byte[] z = cryptGrams[0];
		byte[] t = cryptGrams[1];
		byte[] c = cryptGrams[2];
		
		int byteLen = 512 / 8;
		
		byte[] pw = passPhrase.getBytes();
		byte[] z_pw = util.concatBytes(z, pw);
		
		byte[] ke_ka = Keccak.KMACXOF256(z_pw, $NULL, 1024, $S);
		byte[] ke = Arrays.copyOfRange(ke_ka, 0, byteLen/2);
		byte[] ka = Arrays.copyOfRange(ke_ka, byteLen/2, byteLen);
		
		byte[] m_pre = Keccak.KMACXOF256(ke, $NULL, c.length * 8, $SKE);
		byte[] m = util.xorBytes(m_pre, c);
		byte[] t_p = Keccak.KMACXOF256(ka, m, 512, $SKA);
		
		if (Arrays.equals(t_p, t)) {
			System.out.println(new String(m));
			util.writeByteData(saveAsFile, m);
		}
		else System.out.println(PASS_WRONG);
	}
	
	// Generate an elliptic key pair from a given pass phrase and write the public key to a file.
	// BONUS: Encrypt the private key from that pair under the given password and write it to a different file as well. 
	private static void opt7_GenerateEllipticKey() {
		System.out.println(FILE_NOTES);
		String passPhrase = getConsoleString(PASSPHRASE);
		String publicKeyFile = getUserFileName("key", "save");
		
		byte[] pw = passPhrase.getBytes();
		BigInteger pre_s = util.bytesToBigInt(Keccak.KMACXOF256(pw, $NULL, 512, $SK));
		
		// s is the private key
		BigInteger s = (pre_s.multiply(BigInteger.valueOf(4))).mod(Point.r); // (4 * s) mod r
		
		// V is the public key
		Point V = util.pointMultiplyByScalar(Point.G, s);

		util.writeByteData(publicKeyFile, util.pointDataZip(V));
		
		boolean extra = getYesNoInput(OPT7_EXTRA);
		if (extra) {
			String privateKeyFile = getUserFileName("encrypted private key", "save");
			SecureRandom random = new SecureRandom();
			int byteLen = 512 / 8;
			
			byte[] m = s.toByteArray();
			byte[] z = new byte[byteLen];
			
			random.nextBytes(z);
			
			byte[] z_pw = util.concatBytes(z, pw);
			byte[] ke_ka = Keccak.KMACXOF256(z_pw, $NULL, 1024, $S);
			byte[] ke = Arrays.copyOfRange(ke_ka, 0, byteLen/2);
			byte[] ka = Arrays.copyOfRange(ke_ka, byteLen/2, byteLen);
			byte[] c_pre = Keccak.KMACXOF256(ke, $NULL, m.length * 8, $SKE);
			byte[] c = util.xorBytes(c_pre, m);
			byte[] t = Keccak.KMACXOF256(ka, m, 512, $SKA);
			byte[] Cryptogram = util.concatBytes(z,t,c);
			
			util.writeByteData(privateKeyFile, Cryptogram);
		}
	}
	
	// Encrypt a data file under a given elliptic public key file and write the ciphertext to a file.
	private static void opt8_EncryptFileElliptic() {
		System.out.println(FILE_NOTES);
		byte[] encryptFile =  loadFile("encrypt");
		byte[] keyFile = loadFile("key", "use");
		
		String saveAsFile = getUserFileName("encrypted", "save");
		
		SecureRandom random = new SecureRandom();
		final int byteLen = 512 / 8;
		byte[] pre_k = new byte[byteLen];
		random.nextBytes(pre_k);
		
		BigInteger k = (util.bytesToBigInt(pre_k).multiply(BigInteger.valueOf(4))).mod(Point.r); // (4 * k) mod r
		Point V = util.pointDataUnzip(keyFile);
		
		byte[] m = encryptFile;
		
		Point W = util.pointMultiplyByScalar(V, k);
		Point Z = util.pointMultiplyByScalar(Point.G, k);
		
		byte[] ke_ka = Keccak.KMACXOF256(W.modPtoBytes(), $NULL, 1024, $PK); // W_x mod p
		byte[] ke = Arrays.copyOfRange(ke_ka, 0, byteLen/2);
		byte[] ka = Arrays.copyOfRange(ke_ka, byteLen/2, byteLen);
		
		byte[] c_pre = Keccak.KMACXOF256(ke, $NULL, m.length * 8, $PKE);
		byte[] c = util.xorBytes(c_pre, m);
		
		byte[] t = Keccak.KMACXOF256(ka, m, 512, $PKA);

		byte[] Cryptogram = util.concatBytes(util.pointDataZip(Z), t, c);
		util.writeByteData(saveAsFile, Cryptogram);
	}
	
	// BONUS: Encrypt text input by the user directly to the app instead of
	//        having to read it from a file (but write the ciphertext to a file).
	private static void opt9_EncryptConsoleElliptic() {
		String input = getConsoleString(CONSOLE_GET + "Encrypt: "); // <- TODO FIX it !!!!!
		System.out.println(FILE_NOTES);
		byte[] keyFile = loadFile("key", "use");
		String saveAsFile = getUserFileName("encrypted", "save");
		
		SecureRandom random = new SecureRandom();
		final int byteLen = 512 / 8;
		byte[] pre_k = new byte[byteLen];
		random.nextBytes(pre_k);
		
		BigInteger k = (util.bytesToBigInt(pre_k).multiply(BigInteger.valueOf(4))).mod(Point.r); // (4 * k) mod r
		Point V = util.pointDataUnzip(keyFile);
		
		byte[] m = input.getBytes();
		
		Point W = util.pointMultiplyByScalar(V, k);
		Point Z = util.pointMultiplyByScalar(Point.G, k);
		
		byte[] ke_ka = Keccak.KMACXOF256(W.modPtoBytes(), $NULL, 1024, $PK); // W_x mod p
		byte[] ke = Arrays.copyOfRange(ke_ka, 0, byteLen/2);
		byte[] ka = Arrays.copyOfRange(ke_ka, byteLen/2, byteLen);
		
		byte[] c_pre = Keccak.KMACXOF256(ke, $NULL, m.length * 8, $PKE);
		byte[] c = util.xorBytes(c_pre, m);
		
		byte[] t = Keccak.KMACXOF256(ka, m, 512, $PKA);

		byte[] Cryptogram = util.concatBytes(util.pointDataZip(Z), t, c);
		util.writeByteData(saveAsFile, Cryptogram);
	}
	
	// Decrypt a given elliptic-encrypted file from a given password and write the decrypted data to a file.
	private static void opt10_DecryptFileElliptic() {
		System.out.println(FILE_NOTES);

		byte[][] gramData = loadCryptogram("encrypted", "load");
		String passPhrase = getConsoleString(PASSPHRASE);
		
		byte[] z_bytes = gramData[0];
		byte[] t = gramData[1];
		byte[] c = gramData[2];
		
		Point Z = util.pointDataUnzip(z_bytes);

		byte[] pw = passPhrase.getBytes();
		BigInteger pre_s = util.bytesToBigInt(Keccak.KMACXOF256(pw, $NULL, 512, $SK));
		
		// s is the private key
		BigInteger s = (pre_s.multiply(BigInteger.valueOf(4))).mod(Point.r);
		
		Point W = util.pointMultiplyByScalar(Z, s);

		int byteLen = 512 / 8;
		byte[] ke_ka = Keccak.KMACXOF256(W.modPtoBytes(), $NULL, 1024, $PK);
		byte[] ke = Arrays.copyOfRange(ke_ka, 0, byteLen/2);
		byte[] ka = Arrays.copyOfRange(ke_ka, byteLen/2, byteLen);
		
		byte[] m_pre = Keccak.KMACXOF256(ke, $NULL, c.length * 8, $PKE);
		byte[] m = util.xorBytes(m_pre, c);
		byte[] t_p = Keccak.KMACXOF256(ka, m, 512, $PKA);
		
		if (Arrays.equals(t_p, t)) {
			String saveAsFile = getUserFileName("decrypted", "save");
			util.writeByteData(saveAsFile, m);
		}
		else System.out.println(PASS_WRONG);
	}

	
	// Sign a given file from a given password and write the signature to a file.
	private static void opt11_SignFile() {
		System.out.println(FILE_NOTES);
		byte[] signFile = loadFile("generate a signature for");
		String passPhrase = getConsoleString(PASSPHRASE);
		String saveAsFile = getUserFileName("signature", "save");
		
		byte[] m = signFile;
		byte[] pw = passPhrase.getBytes();
		
		BigInteger pre_s = util.bytesToBigInt(Keccak.KMACXOF256(pw, $NULL, 512, $SK));
		BigInteger s = (pre_s.multiply(BigInteger.valueOf(4))).mod(Point.r);
		
		BigInteger pre_k = util.bytesToBigInt(Keccak.KMACXOF256(s.toByteArray(), m, 512, $N));
		BigInteger k = (pre_k.multiply(BigInteger.valueOf(4))).mod(Point.r);
		
		Point U = util.pointMultiplyByScalar(Point.G, k);
		
		BigInteger h = util.bytesToBigInt(Keccak.KMACXOF256(U.modPtoBytes(), m, 512, $T));
		
		BigInteger pre_z = k.subtract(h.multiply(s));
		BigInteger z = pre_z.mod(Point.r);
		
		byte[] z_bytes = z.toByteArray();
		byte[] h_bytes = h.toByteArray();

		byte[] signature = util.concatBytes(z_bytes, h_bytes);
		util.writeByteData(saveAsFile, signature);
	}

	
	// BONUS: Sign text input by the user directly to the app instead of having
	//        to read it from a file (but write the signature to a file).
	private static void opt12_SignConsole() {
		String input = getConsoleString(CONSOLE_GET + "Sign: ");// <- TODO FIX it !!!!!
		System.out.println(FILE_NOTES);
		String passPhrase = getConsoleString(PASSPHRASE);
		String saveAsFile = getUserFileName("signature", "save");
		
		byte[] m = input.getBytes();
		byte[] pw = passPhrase.getBytes();
		
		BigInteger pre_s = util.bytesToBigInt(Keccak.KMACXOF256(pw, $NULL, 512, $SK));
		BigInteger s = (pre_s.multiply(BigInteger.valueOf(4))).mod(Point.r);
		
		BigInteger pre_k = util.bytesToBigInt(Keccak.KMACXOF256(s.toByteArray(), m, 512, $N));
		BigInteger k = (pre_k.multiply(BigInteger.valueOf(4))).mod(Point.r);
		
		Point U = util.pointMultiplyByScalar(Point.G, k);
		
		BigInteger h = util.bytesToBigInt(Keccak.KMACXOF256(U.modPtoBytes(), m, 512, $T));
		
		BigInteger pre_z = k.subtract(h.multiply(s));
		BigInteger z = pre_z.mod(Point.r);
		
		byte[] z_bytes = z.toByteArray();
		byte[] h_bytes = h.toByteArray();

		byte[] signature = util.concatBytes(z_bytes, h_bytes);
		util.writeByteData(saveAsFile, signature);
	}	
	
	// Verify a given data file and its signature file under a given public key file.
	private static void opt13_VerifyFile() {
		System.out.println(FILE_NOTES);
		byte[] verifyFile = loadFile("verify");
		byte[] sigKeyFile = loadFile("signature", "use");
		byte[] vKeyFile = loadFile("public Key file", "use");

		byte[] m = verifyFile;
		byte[] sign = sigKeyFile;
		Point V = util.pointDataUnzip(vKeyFile);
		if (V == null) {
			System.out.println(NAUGHTY);
			return;
		}

		final int zLen = 56;

		byte[] z_bytes = Arrays.copyOfRange(sign, 0, zLen);
		byte[] h_bytes = Arrays.copyOfRange(sign, zLen, sign.length);

		BigInteger z = new BigInteger(z_bytes);
		BigInteger h = new BigInteger(h_bytes);

		Point G_z = util.pointMultiplyByScalar(Point.G, z);
		Point V_h = util.pointMultiplyByScalar(V, h);

		Point U = G_z.sum(V_h);

		BigInteger h_p = util.bytesToBigInt(Keccak.KMACXOF256(U.modPtoBytes(), m, 512, $T)); // U_x mod p

		if (h.equals(h_p))
			System.out.println(GOOD_SIGN);
		else System.out.println(BAD_SIGN);

	}

	
	private static String getUserFileName(final String... prompts) {
		int i = 0; String fullPrompt = "";
		if (prompts.length > 1) 
			fullPrompt = FILE_P1 + prompts[0] +" "+ FILE_P2 + prompts[1] +": ";
		else fullPrompt = FILE_P1 + FILE_P2 + prompts[0] + ": ";
		
		String filename = null;
		while (filename == null) {
			String userFileName = getConsoleString(fullPrompt);
			if (userFileName.length() > 0 && userFileName.matches(FILE_NAME_REX))
				filename = userFileName;
			else System.out.println(INVALID_FILE_NAME);
		}
		
		if (filename.contains("\\") ||
			filename.contains("\\\\") ||
			filename.contains("\\\\") ||
			filename.contains("/") ||
			filename.contains("//")
			) return filename;
				
		return "./files/"+filename;
	}
	
	private static byte[] loadFile(final String... prompts) {
		byte[] bytes = null;
		while(bytes == null)
			bytes = util.readByteData(getUserFileName(prompts));
		return bytes;
	}
	
	private static byte[][] loadCryptogram(final String... prompts) {
		byte[][] grams = null;
		while(grams == null)
			grams = util.ellipticCryptogramOpener(loadFile(prompts));
		return grams;
	}
	
	private static String getConsoleString(String str) {
		System.out.print(str);
		String userString = scan_man.nextLine();
		System.out.println();
		return userString;
	}

	private static boolean getYesNoInput(final String question) {
		int maxAtempts = 16;
		System.out.println(question);
		while (--maxAtempts > 0) {
			System.out.print(YES_NO);
			String input = scan_man.nextLine().strip().toLowerCase();
			System.out.println();
			
	        final String REGEX = "^[a-z]{1,5}$";
	        
	        if (input.matches(REGEX)) {
	        	if (
	        		input.equals("y")||
	        		input.equals("yes") ||
	        		input.equals("true") ||
	        		input.equals("1")
	        		)
	        		return true;
	        	else if (
	        		input.equals("n") ||
	        		input.equals("no") ||
	        		input.equals("false") ||
	        		input.equals("0")
	        		)
	        		return false;
	        	else {
		        	System.out.println(INVALID_INPUT);
		        	System.out.println(LINE);
	        	}
	        }
	        else { // input didn't match Regex
	        	System.out.println(INVALID_INPUT);
	        	System.out.println(LINE);
	        }
		}
		return false;
	}
	
	private static void getOptionsInput() {
		while (currOpp < 0) {
			printOptions();
			System.out.print("\n"+OPT_SELCT);
			String input = scan_man.nextLine();
			System.out.println();
	        final String REGEX = "^([0-9]|1[0-3])$";
	        if (input.matches(REGEX))
	        	currOpp = (int) Integer.parseInt(input);
	        else {
	        	System.out.println("\""+input+"\"" + OPT_SELCT_BAD);
	        	System.out.println(LINE);
	        }
		}
	}
	
	// Behold the great and powerful Option Selectorator... it is... MAGNIFICENT!
	private static void optionSelected() {
			 if (currOpp ==  0)  running = false;
		else if (currOpp ==  1) {currOpp = -1; opt1_FileHash();}
		else if (currOpp ==  2) {currOpp = -1; opt2_ConsoleHash();}
		else if (currOpp ==  3) {currOpp = -1; opt3_FileMAC();}
		else if (currOpp ==  4) {currOpp = -1; opt4_ConsoleMAC();}
		else if (currOpp ==  5) {currOpp = -1; opt5_EncryptFile();}
		else if (currOpp ==  6) {currOpp = -1; opt6_DecryptFile();}
		else if (currOpp ==  7) {currOpp = -1; opt7_GenerateEllipticKey();}
		else if (currOpp ==  8) {currOpp = -1; opt8_EncryptFileElliptic();}
		else if (currOpp ==  9) {currOpp = -1; opt9_EncryptConsoleElliptic();}
		else if (currOpp == 10) {currOpp = -1; opt10_DecryptFileElliptic();}
		else if (currOpp == 11) {currOpp = -1; opt11_SignFile();}
		else if (currOpp == 12) {currOpp = -1; opt12_SignConsole();}
		else if (currOpp == 13) {currOpp = -1; opt13_VerifyFile();}
		else throw new Error("INVALID OPTION NUMBER");
	}
	private static void printOptions() {
		System.out.println(OPT0);
		System.out.println(P1);
		System.out.println(OPT1);
		System.out.println(OPT2);
		System.out.println(OPT3);
		System.out.println(OPT4);
		System.out.println(OPT5);
		System.out.println(OPT6);
		System.out.println(P2);
		System.out.println(OPT7);
		System.out.println(OPT8);
		System.out.println(OPT9);
		System.out.println(OPT10);
		System.out.println(OPT11);
		System.out.println(OPT12);
		System.out.println(OPT13);
		
	}
	
	private static void printOutput(final byte[] output) {
//		System.out.println(LINE);
		System.out.println(HEXY);
		System.out.print(util.bytesToHexString(output));
		System.out.println();
	}
	
	public static void main(String[] args) {
		scan_man = new Scanner(System.in);
		running = true;
		currOpp = -1;
		
		System.out.println(HELLO);
		while (running) {
			System.out.println(BIGLINE);
			getOptionsInput();
			optionSelected();
		}
		System.out.println(BIGLINE);
		System.out.println(GOODBYE);
	}
	
	public static final byte[]
	   $NULL = new byte[] {0x00},
		  $N = "N".getBytes(),
		  $D = "D".getBytes(),
		  $T = "T".getBytes(),
		  $S = "S".getBytes(),
		$SKE = "SKE".getBytes(),
		$SKA = "SKA".getBytes(),
		 $SK = "SK".getBytes(),
		 $PK = "PK".getBytes(),
		$PKE = "SKE".getBytes(),
		$PKA = "SKA".getBytes();
	
	static final String
		NL = "\n",NL2 = "\n\n",NL3 = "\n\n\n",NL4 = "\n\n\n\n",
		HEXY = "- Byte  Data  Output -",
		INLET = "=> ", OUTLET = " <=",
		LINE = "-------------------------------------------",
		BIGLINE = "--------------------------------------------------------------------------",
		RETRY = "please try again",
	
		HELLO = "Welcome to KMAC-MART! where all your KMAC needs will be fulfilled\n" +
				"Please select one of these generous offerings...",
		GOODBYE = "\nThank you for visiting KMAC-MART, have a great day!",
		
		OPT_SELCT = "Please enter the option you wish to use here (Ctrl-c exits): ",
		OPT_SELCT_BAD = " is not a valid option! You will try again...",
		OPT0 = "\nENTER  0  TO EXIT PROGRAM",
		
		P1    = "\n- - - - P A R T   1   O P T I O N S - - - -",
		OPT1  = "OPTION  1: Compute a plain cryptographic hash of a file",
		OPT2  = "OPTION  2: Compute a plain cryptographic hash of a console input",
		OPT3  = "OPTION  3: Compute a MAC of a given file under a given passphrase",
		OPT4  = "OPTION  4: Compute a MAC of a console input under a given passphrase",
		OPT5  = "OPTION  5: Encrypt a given data file symmetrically under a given passphrase",
		OPT6  = "OPTION  6: Decrypt a given symmetric cryptogram under a given passphrase",
		P2    = "\n- - - - P A R T   2   O P T I O N S - - - -",
		OPT7  = "OPTION  7: Generate an elliptic key pair from a given passphrase",
		OPT8  = "OPTION  8: Encrypt a data file under a given elliptic public key file",
		OPT9  = "OPTION  9: Encrypt your console input under a given elliptic public key file",
		OPT10 = "OPTION 10: Decrypt a given elliptic-encrypted file from a given password",
		OPT11 = "OPTION 11: Sign a given file from a given password",
		OPT12 = "OPTION 12: Sign your console input text from a given password",
		OPT13 = "OPTION 13: Verify a given data file and its signature file",
		
//		FILE_EXP = "* all files are located in the \"files\" sub directory \n",
//		FILE_S	= "Please enter the name (including the extension) of the file you wish to ",
//		FILE_LOAD = FILE_S + "load: ", FILE_SAVE = FILE_S + "save: ",
		
		FILE_NOTES = ":: N O T E ::\n"+
			"Filenames must include any extensions they may have\n"+
			"They may include the full path address of the file\n"+
			"If no path is given, path defaults to the 'files' folder\n",

		FILE_P1 = "Please enter the name of the ", // sign / key / data
		FILE_P2 = "file you wish to ", // load / save / encrypt / decrypt / sign
				
		OPT7_EXTRA = "Would you like to Encrypt the private key and write it to a different file?",
		YES_NO = "Please enter [Y] Yes or [N] No : ",
		CONSOLE_GET = "Below, enter the string you wish to ", // add Hash / MAC in method
		PASSPHRASE = "Please enter your passphrase: ",
		PASS_WRONG = "That is not the correct passphrase: ",

		BAD_SIGN = "The file signature does not match with the given public key!",
		GOOD_SIGN = "The file signature matches with the given public key.",
		
		INVALID_INPUT 		= INLET + "That is not a valid input!",
		INVALID_FILE_NAME 	= INLET + "That is not a valid file name!",
		FILE_NOT_FOUND 		= INLET + "That file could not be located or does not exist!",
		FILE_NOT_ENCRYPTED 	= INLET + "That file is not encrypted or is otherwise incompatible!",
		NAUGHTY = "type type type type type ... computer says no.";
		
	
	
	
	
	private static final String
		FILE_NAME_REX = "^([A-Za-z 0-9_'\\-\\.@!#&,\\^{}\\[\\]=+;$%]*:[\\\\/])?(?![\\\\/])"
			+ "(?!.*\\\\\\\\)(?!.*\\/\\/)(?!.*\\\\\\/)(?!.*\\/\\\\)(?!(.*:){2,})"
			+ "([A-Za-z 0-9/_'\\-\\.@!#&,\\^{}\\\\\\[\\]=+;$%]){0,512}"
			+ "([A-Za-z 0-9_'\\-\\.@!#&,\\^{}\\[\\]=+;$%]){1,64}$";

}



