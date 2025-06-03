package de.bitplumber.crypto.oprf.p384;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.util.BigIntegers;

import de.bitplumber.crypto.oprf.FieldElement;

public class P384FieldElement implements FieldElement {
    private static final ECNamedCurveParameterSpec curveSpec = ECNamedCurveTable.getParameterSpec("secp384r1");
    private static final ECCurve curve = curveSpec.getCurve();
	private final ECFieldElement value;

	public static final P384FieldElement ZERO = new P384FieldElement(BigInteger.ZERO);
	public static final P384FieldElement ONE  = new P384FieldElement(BigInteger.ONE);
	public static final BigInteger ORDER = curve.getField().getCharacteristic();
	public static final int SIZE = 48;

    private P384FieldElement(ECFieldElement value) {
        this.value = value;
    }

    private P384FieldElement(BigInteger value) {
        this.value = curve.fromBigInteger(value);
    }

    public static P384FieldElement randomElement() throws Exception {
        final var rng = SecureRandom.getInstanceStrong();
        return new P384FieldElement(curve.randomFieldElement(rng));
    }

    public static P384FieldElement fromCanonicalBytes(byte[] input) throws Exception {
        final var value = BigIntegers.fromUnsignedByteArray(input);
        if (!curve.isValidFieldElement(value)) throw new IllegalArgumentException("Invalid field element");
		return new P384FieldElement(value);
    }

	public static P384FieldElement fromBytesModOrderWide(byte[] input) {
        final var value = BigIntegers.fromUnsignedByteArray(input).mod(curve.getOrder());
        if (!curve.isValidFieldElement(value)) throw new IllegalArgumentException("Invalid field element");
		return new P384FieldElement(value);
	}

    public byte[] toByteArray() {
		return value.getEncoded();
    }

    public ECFieldElement value() {
        return this.value;
    }

    public P384FieldElement add(FieldElement other) {
		final var otherVal = ((P384FieldElement)other).value();
        return new P384FieldElement(this.value.add(otherVal));
    }

    public P384FieldElement subtract(FieldElement other) {
		final var otherVal = ((P384FieldElement)other).value();
        return new P384FieldElement(this.value.subtract(otherVal));
    }

    public P384FieldElement multiply(FieldElement other) {
		final var otherVal = ((P384FieldElement)other).value();
        return new P384FieldElement(this.value.multiply(otherVal));
    }

    public P384FieldElement invert() {
        return new P384FieldElement(this.value.toBigInteger().modInverse(curve.getOrder()));
    }

    public boolean equals(FieldElement other) {
		final var otherVal = ((P384FieldElement)other).value();
        return this.value.equals(otherVal);
    }

    public boolean ctEquals(FieldElement other) {
		final var otherVal = ((P384FieldElement)other).value();
        return this.value.equals(otherVal);
    }
}
