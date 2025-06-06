package de.bitplumber.crypto.oprf.p521;

import java.math.BigInteger;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import de.bitplumber.crypto.h2c.ECCurveHasher;
import de.bitplumber.crypto.oprf.FieldElement;
import de.bitplumber.crypto.oprf.GroupElement;

public class P521GroupElement implements GroupElement {
	private static final ECNamedCurveParameterSpec curveSpec;
	private static final ECCurve curve;
	private final ECPoint value;

	protected static final int HASH_OUTPUT_SIZE = 64;
	protected static final int HASH_BLOCK_SIZE = 128;

	public static final P521GroupElement BASEPOINT;
	public static final P521GroupElement IDENTITY;
	public static final BigInteger n;	// group order
	public static final BigInteger q;	// prime field order
	public static final int SIZE = 67;

	static {
		curveSpec = ECNamedCurveTable.getParameterSpec("secp521r1");
		curve = curveSpec.getCurve();
		q = curve.getField().getCharacteristic();
		n = curve.getOrder();
		BASEPOINT = new P521GroupElement(curveSpec.getG());
		IDENTITY = new P521GroupElement(curve.getInfinity());
	}

	public P521GroupElement(ECPoint value) {
		this.value = value;
	}

	public static P521GroupElement fromBytes(byte[] input) throws Exception {
		return new P521GroupElement(curveSpec.getCurve().decodePoint(input));
	}

	public static P521GroupElement hashToGroup(byte[] msg, byte[] dst) {
		final var p = ECCurveHasher.createP521().hashToCurve(msg, dst);
		return new P521GroupElement(p);
	}

	public byte[] toByteArray() {
		return this.value.getEncoded(true);
	}

	public ECPoint value() {
		return this.value;
	}

	public P521GroupElement add(GroupElement other) {
		final var otherVal = ((P521GroupElement)other).value();
		return new P521GroupElement(this.value.add(otherVal));
	}

	public P521GroupElement subtract(GroupElement other) {
		final var otherVal = ((P521GroupElement)other).value();
		return new P521GroupElement(this.value.subtract(otherVal));
	}

	public P521GroupElement multiply(FieldElement scalar) {
		final var otherVal = ((P521FieldElement)scalar).value();
		return new P521GroupElement(this.value.multiply(otherVal.toBigInteger()));
	}

    public boolean equals(GroupElement other) {
		final var otherVal = ((P521GroupElement)other).value();
        return this.value.equals(otherVal);
    }

    public boolean ctEquals(GroupElement other) {
		final var otherVal = ((P521GroupElement)other).value();
        return this.value.equals(otherVal);
    }
}
