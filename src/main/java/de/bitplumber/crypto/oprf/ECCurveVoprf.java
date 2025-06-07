package de.bitplumber.crypto.oprf;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

import de.bitplumber.crypto.oprf.ECCurveSuite.Proof;

public class ECCurveVoprf implements Voprf<ECFieldElement, ECPoint, ECCurveVoprf.BlindResult, ECCurveVoprf.BlindEvaluateResult, ECCurveSuite.Proof> {
	public static record BlindResult(ECFieldElement blind, ECPoint blindedElement) {}
	public static final record BlindEvaluateResult(ECPoint evaluatedElement, byte[] proof) {}

    private final ECCurveSuite suite;
	private final byte[] context;

	public ECCurveVoprf(final ECCurveSuite suite) {
        this.suite  = suite;
		this.context = Arrays.concatenate(new byte[][]{
			Labels.CONTEXT_PREFIX, Modes.VOPRF,
			("-" + suite.getName()).getBytes(StandardCharsets.UTF_8),
		});
	}

	public static ECCurveVoprf createP256() {
		return new ECCurveVoprf(ECCurveSuite.createP256());
	}

	public static ECCurveVoprf createP384() {
		return new ECCurveVoprf(ECCurveSuite.createP384());
	}

	public static ECCurveVoprf createP521() {
		return new ECCurveVoprf(ECCurveSuite.createP521());
	}

	public KeyPair randomKeyPair() {
		return suite.randomKeyPair();
	}

	public KeyPair deriveKeyPair(byte[] seed, byte[] info) throws Exception {
		return suite.deriveKeyPair(seed, info, context);
	}

	public byte[] encodeElement(ECPoint element) {
		return suite.encodeElement(element);
	}

	public ECPoint decodeElement(byte[] encoded) {
		return suite.decodeElement(encoded);
	}

	public ECFieldElement randomScalar() {
		return suite.randomScalar();
	}

	public byte[] encodeScalar(ECFieldElement scalar) {
		return suite.encodeScalar(scalar);
	}

	public ECFieldElement decodeScalar(byte[] encoded) {
		return suite.decodeScalar(encoded);
	}

	public Proof decodeProof(byte[] encoded) {
		return Proof.fromBytes(suite, encoded);
	}

	public byte[] encodeProof(Proof proof) {
		return proof.toByteArray();
	}

	private BlindResult doBlind(byte[] input, ECFieldElement blind) throws Exception {
		final var inputElement = suite.hashToGroup(input, null, context);
		if (inputElement.isInfinity() || !inputElement.isValid())
			throw new IllegalArgumentException("InvalidInputError");

		final var blindedElement = inputElement.multiply(blind.toBigInteger());
		return new BlindResult(blind, blindedElement);
	}

	protected BlindResult blind(byte[] input, byte[] blind) throws Exception {
		return doBlind(input, blind == null ? suite.randomScalar() : suite.decodeScalar(blind));
	}

	public BlindResult blind(byte[] input) throws Exception {
		return doBlind(input, suite.randomScalar());
	}

	private BlindEvaluateResult doBlindEvaluate(byte[] serverSecretKey, byte[] serverPublicKey, ECPoint blindedElement, ECFieldElement proofRandomScalar) throws Exception {
		final var skS = suite.decodeScalar(serverSecretKey);
		final var pkS = suite.decodeElement(serverPublicKey);
		final var evaluatedElement = blindedElement.multiply(skS.toBigInteger());
		final var blindedElements  = new ECPoint[]{ blindedElement };
		final var evaluatedElements = new ECPoint[]{ evaluatedElement };
		final var proof = suite.generateProof(skS, suite.getG(), pkS, blindedElements, evaluatedElements, proofRandomScalar, context);
		return new BlindEvaluateResult(evaluatedElement, encodeProof(proof));
	}

	protected BlindEvaluateResult blindEvaluate(byte[] serverSecretKey, byte[] serverPublicKey, ECPoint blindedElement, byte[] proofRandomScalar) throws Exception {
		return doBlindEvaluate(serverSecretKey, serverPublicKey, blindedElement, proofRandomScalar == null ? null : suite.decodeScalar(proofRandomScalar));
	}

	public BlindEvaluateResult blindEvaluate(byte[] serverSecretKey, byte[] serverPublicKey, ECPoint blindedElement) throws Exception {
		return doBlindEvaluate(serverSecretKey, serverPublicKey, blindedElement, null);
	}

	public byte[] finalize(byte[] input, ECFieldElement blind, ECPoint evaluatedElement, ECPoint blindedElement, byte[] serverPublicKey, Proof proof) throws Exception {
		final var pkS = suite.decodeElement(serverPublicKey);
		final var blindedElements = new ECPoint[]{ blindedElement };
		final var evaluatedElements = new ECPoint[]{ evaluatedElement };
		if (!suite.verifyProof(suite.getG(), pkS, blindedElements, evaluatedElements, proof, context))
			throw new Exception("Failed to verify proof");

		final var invBlind = suite.invertScalar(blind);
		final var n = evaluatedElement.multiply(invBlind.toBigInteger());
		final var unblindedElement = suite.encodeElement(n);
		return suite.hash(Arrays.concatenate(new byte[][]{
			suite.I2OSP(input.length, 2), input,
			suite.I2OSP(unblindedElement.length, 2), unblindedElement,
			Labels.FINALIZE
		}));
	}

	public byte[] evaluate(byte[] serverSecretKey, byte[] input) throws Exception {
		final var inputElement = suite.hashToGroup(input, null, context);
		if (inputElement.isInfinity() || !inputElement.isValid())
			throw new IllegalArgumentException("InvalidInputError");

		final var skS = suite.decodeScalar(serverSecretKey);
		final var evaluatedElement = inputElement.multiply(skS.toBigInteger());
		final var issuedElement = suite.encodeElement(evaluatedElement);

		return suite.hash(Arrays.concatenate(new byte[][]{
			suite.I2OSP(input.length, 2), input,
			suite.I2OSP(issuedElement.length, 2), issuedElement,
			Labels.FINALIZE
		}));
	}

}
