import Exceptions.InvalidSignature;
import messages.InitialMessageResponse;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class User {

    private String name;
    private static KeyPairGenerator keyPairGen;

    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    static {
        try {
            keyPairGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public User(String name) {
        this.name = name;
        KeyPair keyPair = User.keyPairGen.generateKeyPair();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
    }

    private BigInteger generateRandomNumber() {
        return DHPublicParams.generateBigPrimeNumber(DHPublicParams.PRIME_LENGTH);
    }

    private void printBytes(byte[] byteArray) {

        StringBuilder sb = new StringBuilder();

        for (byte b : byteArray)
        {
            sb.append(String.format("%02X ", b));
        }
        System.out.println(sb.toString());
    }

    private Key getKeyFromBigInt(BigInteger input) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = input.toByteArray();

        return new SecretKeySpec(Arrays.copyOf(keyBytes, 32), "AES");
    }

    private byte[] sign(byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(this.privateKey);

        signature.update(data);

        return signature.sign();
    }

    private boolean verifySignature(byte[] signedData, byte[] plainData,  PublicKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(key);
        signature.update(plainData);

        boolean valid = signature.verify(signedData);
        return valid;
    }

    private byte[] encrypt(byte[] data, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public InitialMessageResponse receiveInitialMessage(BigInteger exp) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException, SignatureException {
        BigInteger bigNumber = this.generateRandomNumber();
        BigInteger myExp = DHPublicParams.BASE.modPow(bigNumber, DHPublicParams.LIMIT);

        BigInteger key = myExp.modPow(exp, DHPublicParams.LIMIT);
        Key sharedKey = this.getKeyFromBigInt(key);

        byte[] encryptedSignature = this.encrypt(
                this.sign(key.toByteArray()),
                sharedKey
        );

        return new InitialMessageResponse(myExp, encryptedSignature);
    }

    private void verifyToken(byte[] encryptedToken, byte[] originalData, Key sharedKey, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException, InvalidSignature {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, sharedKey);
        byte[] signature = cipher.doFinal(encryptedToken);

        boolean isValid = this.verifySignature(signature, originalData, publicKey);

        if(!isValid) throw new InvalidSignature();

        System.out.println(this.name + ": ");
        System.out.println("Message is OK.");
        System.out.print("Key is: ");
        printBytes(originalData);
    }

    public void establishCommunication(User user) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidKeySpecException, SignatureException, InvalidSignature {

        BigInteger bigNumber = this.generateRandomNumber();
        BigInteger myExp = DHPublicParams.BASE.modPow(bigNumber, DHPublicParams.LIMIT);

        InitialMessageResponse msg = user.receiveInitialMessage(myExp);

        BigInteger key = msg.getExp().modPow(myExp, DHPublicParams.LIMIT);
        Key sharedKey = this.getKeyFromBigInt(key);
        try {
            this.verifyToken(msg.getToken(), key.toByteArray(), sharedKey, user.getPublicKey());
        }
        catch (InvalidSignature e) {
            System.out.println("Invalid signature");
            return;
        }

        // Send the second message from Alice to Bob
        byte[] toSend = this.encrypt(
                this.sign(key.toByteArray()),
                sharedKey
        );

//
        try {
            // Verify the second message
            user.verifyToken(toSend, key.toByteArray(), sharedKey, this.publicKey);
        }
        catch (InvalidSignature e) {
            System.out.println("Invalid signature");
            return;
        }
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }
}
