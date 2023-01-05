package messages;

import java.math.BigInteger;

public class InitialMessageResponse {

    private BigInteger exp;
    private byte[] token;

    public InitialMessageResponse(BigInteger exp, byte[] token) {
        this.exp = exp;
        this.token = token;
    }

    public BigInteger getExp() {
        return this.exp;
    }

    public byte[] getToken() {
        return this.token;
    }
}
