package de.bitplumber.crypto.oprf.p256;

import java.math.BigInteger;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import de.bitplumber.crypto.h2c.ECCurveHasher;
import de.bitplumber.crypto.oprf.FieldElement;
import de.bitplumber.crypto.oprf.GroupElement;

public class P256GroupElement implements GroupElement {
	private static final ECNamedCurveParameterSpec curveSpec;
	private static final ECCurve curve;
	private final ECPoint value;

	protected static final int HASH_OUTPUT_SIZE = 32;
	protected static final int HASH_BLOCK_SIZE = 64;

	public static final P256GroupElement BASEPOINT;
	public static final P256GroupElement IDENTITY;
	public static final BigInteger n;	// group order
	public static final BigInteger q;	// prime field order
	public static final int SIZE = 33;

	static {
		curveSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
		curve = curveSpec.getCurve();
		q = curve.getField().getCharacteristic();
		n = curve.getOrder();
		BASEPOINT = new P256GroupElement(curveSpec.getG());
		IDENTITY = new P256GroupElement(curve.getInfinity());
	}

	public P256GroupElement(ECPoint value) {
		this.value = value;
	}

	public static P256GroupElement fromBytes(byte[] input) throws Exception {
		return new P256GroupElement(curveSpec.getCurve().decodePoint(input));
	}

	public static P256GroupElement hashToGroup(byte[] msg, byte[] dst) {
		final var p = ECCurveHasher.createP256().hashToCurve(msg, dst);
		return new P256GroupElement(p);
	}

	public byte[] toByteArray() {
		return this.value.getEncoded(true);
	}

	public ECPoint value() {
		return this.value;
	}

	public P256GroupElement add(GroupElement other) {
		final var otherVal = ((P256GroupElement)other).value();
		return new P256GroupElement(this.value.add(otherVal));
	}

	public P256GroupElement subtract(GroupElement other) {
		final var otherVal = ((P256GroupElement)other).value();
		return new P256GroupElement(this.value.subtract(otherVal));
	}

	public P256GroupElement multiply(FieldElement scalar) {
		final var otherVal = ((P256FieldElement)scalar).value();
		return new P256GroupElement(this.value.multiply(otherVal.toBigInteger()));
	}

    public boolean equals(GroupElement other) {
		final var otherVal = ((P256GroupElement)other).value();
        return this.value.equals(otherVal);
    }

    public boolean ctEquals(GroupElement other) {
		final var otherVal = ((P256GroupElement)other).value();
        return this.value.equals(otherVal);
    }
}
