import java.math.BigInteger;
import java.security.SecureRandom;

public class DHPublicParams {

    private static final SecureRandom random = new SecureRandom();

    public static final int PRIME_LENGTH = 256;
    public static final BigInteger BASE = DHPublicParams.generateBigPrimeNumber(PRIME_LENGTH);
    public static final BigInteger LIMIT =  DHPublicParams.generateBigPrimeNumber(PRIME_LENGTH);

    public static BigInteger generateBigPrimeNumber(int bits) {
        return BigInteger.probablePrime(bits, random);
    }
}
