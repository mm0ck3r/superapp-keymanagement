package main.java.superapp.keymanagement;

import org.bitcoinj.core.SegwitAddress;
import org.web3j.crypto.exception.CipherException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.crypto.generators.SCrypt;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.util.Arrays;
import java.math.BigInteger;
import java.io.File;
import java.util.UUID;
import java.time.format.DateTimeFormatter;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.bitcoinj.core.DumpedPrivateKey;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.LegacyAddress;

public class BitcoinKeystoreUtils {
    private static final String HEX_PREFIX = "0x";
    private static final char[] HEX_CHAR_MAP = "0123456789abcdef".toCharArray();
    private static final ObjectMapper objectMapper = new ObjectMapper();

    static{
        objectMapper.configure(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES, true);
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    static byte[] generateRandomBytes(int size) {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[size];
        random.nextBytes(bytes);
        return bytes;
    }

    public static byte[] sha3(byte[] input, int offset, int length){
        Keccak.DigestKeccak kecc = new Keccak.Digest256();
        kecc.update(input, offset, length);
        return kecc.digest();
    }
    public static byte[] sha3(byte[] input) {
        return sha3(input, 0, input.length);
    }

    private static byte[] generateMac(byte[] derivedKey, byte[] cipherText) {
        byte[] result = new byte[16 + cipherText.length];

        System.arraycopy(derivedKey, 16, result, 0, 16);
        System.arraycopy(cipherText, 0, result, 16, cipherText.length);

        return sha3(result);
    }

    public static String toHexString(byte[] input, int offset, int length, boolean withPrefix) {
        final String output = new String(toHexCharArray(input, offset, length));
        return withPrefix ? new StringBuilder(HEX_PREFIX).append(output).toString() : output;
    }
    private static char[] toHexCharArray(byte[] input, int offset, int length) {
        final char[] output = new char[length << 1];
        for (int i = offset, j = 0; i < length + offset; i++, j++) {
            final int v = input[i] & 0xFF;
            output[j++] = HEX_CHAR_MAP[v >>> 4];
            output[j] = HEX_CHAR_MAP[v & 0x0F];
        }
        return output;
    }
    public static boolean SisEmpty(String s) {
        return s == null || s.isEmpty();
    }
    public static boolean containsHexPrefix(String input) {
        return !SisEmpty(input)
                && input.length() > 1
                && input.charAt(0) == '0'
                && input.charAt(1) == 'x';
    }
    public static String cleanHexPrefix(String input) {
        if (containsHexPrefix(input)) {
            return input.substring(2);
        } else {
            return input;
        }
    }
    public static byte[] hexStringToByteArray(String input) {
        String cleanInput = cleanHexPrefix(input);

        int len = cleanInput.length();

        if (len == 0) {
            return new byte[] {};
        }

        byte[] data;
        int startIdx;
        if (len % 2 != 0) {
            data = new byte[(len / 2) + 1];
            data[0] = (byte) Character.digit(cleanInput.charAt(0), 16);
            startIdx = 1;
        } else {
            data = new byte[len / 2];
            startIdx = 0;
        }

        for (int i = startIdx; i < len; i += 2) {
            data[(i + 1) / 2] =
                    (byte)
                            ((Character.digit(cleanInput.charAt(i), 16) << 4)
                                    + Character.digit(cleanInput.charAt(i + 1), 16));
        }
        return data;
    }
    public static byte[] toBytesPadded(BigInteger value, int length) {
        byte[] result = new byte[length];
        byte[] bytes = value.toByteArray();

        int bytesLength;
        int srcOffset;
        if (bytes[0] == 0) {
            bytesLength = bytes.length - 1;
            srcOffset = 1;
        } else {
            bytesLength = bytes.length;
            srcOffset = 0;
        }

        if (bytesLength > length) {
            throw new RuntimeException("Input is too large to put in byte array of size " + length);
        }

        int destOffset = length - bytesLength;
        System.arraycopy(bytes, srcOffset, result, destOffset, bytesLength);
        return result;
    }

    public static String toHexStringNoPrefix(byte[] input) {
        return toHexString(input, 0, input.length, false);
    }

    public static String generateWalletFile(String Password, File destinationDirectory, NetworkParameters params) throws Exception{
        ECKey bitcoinKey = new ECKey(); // bitcoin private Key
        String PrivateKey = bitcoinKey.getPrivateKeyAsHex(); // 비트코인 개인키는 그냥 난수임.(SecureRandom)
        SegwitAddress segwitAddr = SegwitAddress.fromKey(params, bitcoinKey);
        String address = segwitAddr.toString();
        // 1. Password로 Derived Key 생성하기 (SCRYPT)
        byte[] salt = generateRandomBytes(32);

        byte[] derivedKey = SCrypt.generate(Password.getBytes(UTF_8), salt, 1 << 12, 8, 6, 32);
        byte[] encryptKey = Arrays.copyOfRange(derivedKey, 0, 16);

        // 2. AES Encryption
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

        byte[] iv = generateRandomBytes(16);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        BigInteger privateKeyBig = new BigInteger(PrivateKey, 16);
        byte[] privateKeyBytes = toBytesPadded(privateKeyBig, 32);

        SecretKeySpec derivedKeySpec = new SecretKeySpec(encryptKey, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, derivedKeySpec, ivSpec);
        byte[] cipherText = cipher.doFinal(privateKeyBytes);

        // Generate Mac value
        byte[] mac = generateMac(derivedKey, cipherText);

        System.out.println("개인키: "+PrivateKey);
        System.out.println("Mac: " + toHexString(mac, 0, mac.length, false));

        // how to make & return JSONObject
        //TODO

        bWalletFile bwalletFile = new bWalletFile();
        bwalletFile.setAddress(address);

        bWalletFile.Crypto crypto = new bWalletFile.Crypto();
        crypto.setCipher("aes-128-ctr");
        crypto.setCiphertext(toHexStringNoPrefix(cipherText));

        bWalletFile.CipherParams cipherParams = new bWalletFile.CipherParams();
        cipherParams.setIv(toHexStringNoPrefix(iv));
        crypto.setCipherparams(cipherParams);

        crypto.setKdf("scrypt");
        bWalletFile.ScryptKdfParams kdfParams = new bWalletFile.ScryptKdfParams();
        kdfParams.setDklen(32);
        kdfParams.setN(262144);
        kdfParams.setP(1);
        kdfParams.setR(8);
        kdfParams.setSalt(toHexStringNoPrefix(salt));
        crypto.setKdfparams(kdfParams);

        crypto.setMac(toHexStringNoPrefix(mac));
        bwalletFile.setCrypto(crypto);
        bwalletFile.setId(UUID.randomUUID().toString());
        bwalletFile.setVersion(1);

        DateTimeFormatter format = DateTimeFormatter.ofPattern("'UTC--'yyyy-MM-dd'T'HH-mm-ss.nVV'--'");
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        String fileName = now.format(format) + bwalletFile.getAddress() + ".json";

        File Destination = new File(destinationDirectory, fileName);

        objectMapper.writeValue(Destination, bwalletFile);
        return fileName;
    }

    public static void compareMac(String Password) throws Exception{
        //TODO: UPDATE
        String PrivateKey = "[**HIDEN**]";
        String strSalt = "[**HIDEN**]";
        String strIv = "[**HIDEN**]";
        byte[] salt = hexStringToByteArray(strSalt);
        byte[] iv = hexStringToByteArray(strIv);

        byte[] derivedKey = SCrypt.generate(Password.getBytes(UTF_8), salt, 262144, 8, 1, 32);
        byte[] encryptKey = Arrays.copyOfRange(derivedKey, 0, 16);


        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        BigInteger privateKeyBig = new BigInteger(PrivateKey, 16);
        byte[] privateKeyBytes = toBytesPadded(privateKeyBig, 32);
        SecretKeySpec derivedKeySpec = new SecretKeySpec(encryptKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, derivedKeySpec, ivSpec);
        byte[] cipherText = cipher.doFinal(privateKeyBytes);


        // Generate Mac value
        byte[] mac = generateMac(derivedKey, cipherText);
        System.out.println("AES CipherText: " +toHexString(cipherText, 0, mac.length, false));
        System.out.println("Mac: "+toHexString(mac, 0, mac.length, false));
    }
    static void validate(bWalletFile bwalletFile) throws CipherException {
        bWalletFile.Crypto crypto = bwalletFile.getCrypto();

        if (bwalletFile.getVersion() != 1) {
            throw new CipherException("Wallet version is not supported");
        }

        if (!crypto.getCipher().equals("aes-128-ctr")) {
            throw new CipherException("Wallet cipher is not supported");
        }

        if (!crypto.getKdf().equals("pbkdf2") && !crypto.getKdf().equals("scrypt")) {
            throw new CipherException("KDF type is not supported");
        }
    }
    public static bitCredentials decrypt(String password, bWalletFile bwalletFile) throws CipherException{
        validate(bwalletFile);

        bWalletFile.Crypto crypto = bwalletFile.getCrypto();

        byte[] mac = hexStringToByteArray(crypto.getMac());
        byte[] iv = hexStringToByteArray(crypto.getCipherparams().getIv());
        byte[] cipherText = hexStringToByteArray(crypto.getCiphertext());

        byte[] derivedKey;

        bWalletFile.KdfParams kdfParams = crypto.getKdfparams();
        if(kdfParams instanceof bWalletFile.ScryptKdfParams){
            bWalletFile.ScryptKdfParams scryptKdfParams = (bWalletFile.ScryptKdfParams) crypto.getKdfparams();
            int dklen = scryptKdfParams.getDklen();
            int n = scryptKdfParams.getN();
            int p = scryptKdfParams.getP();
            int r = scryptKdfParams.getR();
            byte[] salt = hexStringToByteArray(scryptKdfParams.getSalt());
            derivedKey = SCrypt.generate(password.getBytes(UTF_8), salt, n, r, p, dklen);
        }
        // TODO: 아니면 어떡하는데?
        else{
            throw new CipherException("Unable to deserialize params: " + crypto.getKdf());
        }

        byte[] derivedMac = generateMac(derivedKey, cipherText);

        if(!Arrays.equals(derivedMac, mac)){
            throw new CipherException("Invalid Password provided");
        }

        byte[] encryptKey = Arrays.copyOfRange(derivedKey, 0, 16);
        byte[] privateKey;
        // byte[] privateKey = performCipherOperation(Cipher.DECRYPT_MODE, iv, encryptKey, cipherText);
        try{
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(encryptKey, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            privateKey = cipher.doFinal(cipherText);
        } catch (NoSuchPaddingException
                 | NoSuchAlgorithmException
                 | InvalidAlgorithmParameterException
                 | InvalidKeyException
                 | IllegalBlockSizeException
                 | BadPaddingException e) {
            throw new CipherException("Error performing cipher operation", e);
        }
        return new bitCredentials(bwalletFile.getAddress(), toHexStringNoPrefix(privateKey));
    }

    public static bitCredentials loadBitCredentials(String password, String source) throws Exception{
        bWalletFile bwalletFile = objectMapper.readValue(new File(source), bWalletFile.class);
        return decrypt(password, bwalletFile);
    }

    public static ECKey.ECDSASignature bitSign(String address, String privateKeyHex, NetworkParameters params, String message){
        BigInteger privateKeyBigInt = new BigInteger(privateKeyHex, 16);
        ECKey key = ECKey.fromPrivate(privateKeyBigInt);
        String privateKeyWIF = key.getPrivateKeyAsWiF(params);

        ECKey privateKey = DumpedPrivateKey.fromBase58(params, privateKeyWIF).getKey();
        byte[] messageHash = Sha256Hash.hash(message.getBytes());
        System.out.println(messageHash.length);

        ECKey.ECDSASignature signature = privateKey.sign(Sha256Hash.wrap(messageHash));
        String signatureBase64 = Utils.HEX.encode(signature.encodeToDER());
        System.out.println(signatureBase64);

        boolean isValid = privateKey.verify(Sha256Hash.wrap(messageHash), signature);
        System.out.println("서명 검증 결과: " + isValid);

        return signature;
    }
}