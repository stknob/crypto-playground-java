package de.bitplumber.crypto.oprf.p521;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.util.BigIntegers;

import de.bitplumber.crypto.oprf.FieldElement;

public class P521FieldElement implements FieldElement {
    private static final ECNamedCurveParameterSpec curveSpec = ECNamedCurveTable.getParameterSpec("secp521r1");
    private static final ECCurve curve = curveSpec.getCurve();
	private final ECFieldElement value;

	public static final P521FieldElement ZERO = new P521FieldElement(BigInteger.ZERO);
	public static final P521FieldElement ONE  = new P521FieldElement(BigInteger.ONE);
	public static final BigInteger ORDER = curve.getField().getCharacteristic();
	public static final int SIZE = 66;

    private P521FieldElement(ECFieldElement value) {
        this.value = value;
    }

    private P521FieldElement(BigInteger value) {
        this.value = curve.fromBigInteger(value);
    }

    public static P521FieldElement randomElement() throws Exception {
        final var rng = SecureRandom.getInstanceStrong();
        return new P521FieldElement(curve.randomFieldElement(rng));
    }

    public static P521FieldElement fromCanonicalBytes(byte[] input) throws Exception {
        final var value = BigIntegers.fromUnsignedByteArray(input);
        if (!curve.isValidFieldElement(value)) throw new IllegalArgumentException("Invalid field element");
		return new P521FieldElement(value);
    }

	public static P521FieldElement fromBytesModOrderWide(byte[] uniformBytes) {
        final var value = BigIntegers.fromUnsignedByteArray(uniformBytes).mod(curve.getOrder());
        if (!curve.isValidFieldElement(value)) throw new IllegalArgumentException("Invalid field element");
		return new P521FieldElement(value);
	}

    public byte[] toByteArray() {
		return value.getEncoded();
    }

    public ECFieldElement value() {
        return this.value;
    }

    public P521FieldElement add(FieldElement other) {
		final var otherVal = ((P521FieldElement)other).value();
        return new P521FieldElement(this.value.add(otherVal));
    }

    public P521FieldElement subtract(FieldElement other) {
		final var otherVal = ((P521FieldElement)other).value();
        return new P521FieldElement(this.value.subtract(otherVal));
    }

    public P521FieldElement multiply(FieldElement other) {
		final var otherVal = ((P521FieldElement)other).value();
        return new P521FieldElement(this.value.multiply(otherVal));
    }

    public P521FieldElement invert() {
        return new P521FieldElement(this.value.toBigInteger().modInverse(curve.getOrder()));
    }

    public boolean equals(FieldElement other) {
		final var otherVal = ((P521FieldElement)other).value();
        return this.value.equals(otherVal);
    }

    public boolean ctEquals(FieldElement other) {
		final var otherVal = ((P521FieldElement)other).value();
        return this.value.equals(otherVal);
    }
}
