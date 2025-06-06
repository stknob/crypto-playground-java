package de.bitplumber.crypto.oprf.p384;

import java.math.BigInteger;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import de.bitplumber.crypto.h2c.ECCurveHasher;
import de.bitplumber.crypto.oprf.FieldElement;
import de.bitplumber.crypto.oprf.GroupElement;

public class P384GroupElement implements GroupElement {
	private static final ECNamedCurveParameterSpec curveSpec;
	private static final ECCurve curve;
	private final ECPoint value;

	protected static final int HASH_OUTPUT_SIZE = 48;
	protected static final int HASH_BLOCK_SIZE = 128;

	public static final P384GroupElement BASEPOINT;
	public static final P384GroupElement IDENTITY;
	public static final BigInteger n;	// group order
	public static final BigInteger q;	// prime field order
	public static final int SIZE = 49;

	static {
		curveSpec = ECNamedCurveTable.getParameterSpec("secp384r1");
		curve = curveSpec.getCurve();
		q = curve.getField().getCharacteristic();
		n = curve.getOrder();
		BASEPOINT = new P384GroupElement(curveSpec.getG());
		IDENTITY = new P384GroupElement(curve.getInfinity());
	}

	public P384GroupElement(ECPoint value) {
		this.value = value;
	}

	public static P384GroupElement fromBytes(byte[] input) throws Exception {
		return new P384GroupElement(curveSpec.getCurve().decodePoint(input));
	}

	public static P384GroupElement hashToGroup(byte[] msg, byte[] dst) {
		final var p = ECCurveHasher.createP384().hashToCurve(msg, dst);
		return new P384GroupElement(p);
	}

	public byte[] toByteArray() {
		return this.value.getEncoded(true);
	}

	public ECPoint value() {
		return this.value;
	}

	public P384GroupElement add(GroupElement other) {
		final var otherVal = ((P384GroupElement)other).value();
		return new P384GroupElement(this.value.add(otherVal));
	}

	public P384GroupElement subtract(GroupElement other) {
		final var otherVal = ((P384GroupElement)other).value();
		return new P384GroupElement(this.value.subtract(otherVal));
	}

	public P384GroupElement multiply(FieldElement scalar) {
		final var otherVal = ((P384FieldElement)scalar).value();
		return new P384GroupElement(this.value.multiply(otherVal.toBigInteger()));
	}

    public boolean equals(GroupElement other) {
		final var otherVal = ((P384GroupElement)other).value();
        return this.value.equals(otherVal);
    }

    public boolean ctEquals(GroupElement other) {
		final var otherVal = ((P384GroupElement)other).value();
        return this.value.equals(otherVal);
    }
}
