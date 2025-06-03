package de.bitplumber.crypto.oprf.p256;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.util.BigIntegers;

import de.bitplumber.crypto.oprf.FieldElement;

public class P256FieldElement implements FieldElement {
    private static final ECNamedCurveParameterSpec curveSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
    private static final ECCurve curve = curveSpec.getCurve();
	private final ECFieldElement value;

	protected static final int HASH_OUTPUT_SIZE = 32;
	protected static final int HASH_BLOCK_SIZE = 64;

	public static final P256FieldElement ZERO = new P256FieldElement(BigInteger.ZERO);
	public static final P256FieldElement ONE  = new P256FieldElement(BigInteger.ONE);
	public static final BigInteger ORDER = curve.getField().getCharacteristic();
	public static final int SIZE = 32;

    private P256FieldElement(ECFieldElement value) {
        this.value = value;
    }

    private P256FieldElement(BigInteger value) {
        this.value = curve.fromBigInteger(value);
    }

    public static P256FieldElement randomElement() throws Exception {
        final var rng = SecureRandom.getInstanceStrong();
        return new P256FieldElement(curve.randomFieldElement(rng));
    }

    public static P256FieldElement fromCanonicalBytes(byte[] input) throws Exception {
        final var value = BigIntegers.fromUnsignedByteArray(input);
        if (!curve.isValidFieldElement(value)) throw new IllegalArgumentException("Invalid field element");
		return new P256FieldElement(value);
    }

	public static P256FieldElement fromBytesModOrderWide(byte[] input) {
        final var value = BigIntegers.fromUnsignedByteArray(input).mod(curve.getOrder());
        if (!curve.isValidFieldElement(value)) throw new IllegalArgumentException("Invalid field element");
		return new P256FieldElement(value);
	}

    public byte[] toByteArray() {
		return value.getEncoded();
    }

    public ECFieldElement value() {
        return this.value;
    }

    public P256FieldElement add(FieldElement other) {
		final var otherVal = ((P256FieldElement)other).value();
        return new P256FieldElement(this.value.add(otherVal));
    }

    public P256FieldElement subtract(FieldElement other) {
		final var otherVal = ((P256FieldElement)other).value();
        return new P256FieldElement(this.value.subtract(otherVal));
    }

    public P256FieldElement multiply(FieldElement other) {
		final var otherVal = ((P256FieldElement)other).value();
        return new P256FieldElement(this.value.multiply(otherVal));
    }

    public P256FieldElement invert() {
        return new P256FieldElement(this.value.toBigInteger().modInverse(curve.getOrder()));
    }

    public boolean equals(FieldElement other) {
		final var otherVal = ((P256FieldElement)other).value();
        return this.value.equals(otherVal);
    }

    public boolean ctEquals(FieldElement other) {
		final var otherVal = ((P256FieldElement)other).value();
        return this.value.equals(otherVal);
    }
}
