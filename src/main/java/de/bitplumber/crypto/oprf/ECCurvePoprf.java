package de.bitplumber.crypto.oprf;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

import de.bitplumber.crypto.oprf.ECCurveSuite.ECScalar;
import de.bitplumber.crypto.oprf.ECCurveSuite.Proof;

public class ECCurvePoprf implements Poprf<ECScalar, ECPoint, ECCurvePoprf.BlindResult, ECCurvePoprf.BlindEvaluateResult, ECCurveSuite.Proof> {
	public static record BlindResult(ECScalar blind, ECPoint blindedElement, ECPoint tweakedKey) {}
	public static final record BlindEvaluateResult(ECPoint evaluatedElement, byte[] proof) {}

    private final ECCurveSuite suite;
	private final byte[] context;

	public ECCurvePoprf(final ECCurveSuite suite) {
        this.suite  = suite;
		this.context = Arrays.concatenate(new byte[][]{
			Labels.CONTEXT_PREFIX, Modes.POPRF,
			("-" + suite.getName()).getBytes(StandardCharsets.UTF_8),
		});
	}

	public static ECCurvePoprf createP256() {
		return new ECCurvePoprf(ECCurveSuite.createP256());
	}

	public static ECCurvePoprf createP384() {
		return new ECCurvePoprf(ECCurveSuite.createP384());
	}

	public static ECCurvePoprf createP521() {
		return new ECCurvePoprf(ECCurveSuite.createP521());
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

	public ECScalar randomScalar() {
		return suite.randomScalar();
	}

	public byte[] encodeScalar(ECScalar scalar) {
		return suite.encodeScalar(scalar);
	}

	public ECScalar decodeScalar(byte[] encoded) {
		return suite.decodeScalar(encoded);
	}

	public Proof decodeProof(byte[] encoded) {
		return Proof.fromBytes(suite, encoded);
	}

	public byte[] encodeProof(Proof proof) {
		return proof.toByteArray();
	}

	private BlindResult doBlind(byte[] input, byte[] info, byte[] serverPublicKey, ECScalar blind) throws Exception {
		final var pkS = suite.decodeElement(serverPublicKey);
		final var framedInfo = Arrays.concatenate(Labels.INFO, suite.I2OSP(info.length, 2), info);
		final var m = suite.hashToScalar(framedInfo, null, context);
		final var T = suite.getG().multiply(m.toBigInteger());
		final var tweakedKey = T.add(pkS);
		if (!tweakedKey.isValid() || tweakedKey.isInfinity())
			throw new IllegalArgumentException("InvalidInputError");

		final var inputElement = suite.hashToGroup(input, null, context);
		if (!inputElement.isValid() || inputElement.isInfinity())
			throw new IllegalArgumentException("InvalidInputError");

		final var blindedElement = inputElement.multiply(blind.toBigInteger());
		return new BlindResult(blind, blindedElement, tweakedKey);
	}

	protected BlindResult blind(byte[] input, byte[] info, byte[] serverPublicKey, byte[] blind) throws Exception {
		Objects.requireNonNull(blind, "Mandatory parameter 'blind' missing");
		return doBlind(input, info, serverPublicKey, suite.decodeScalar(blind));
	}

	public BlindResult blind(byte[] input, byte[] info, byte[] serverPublicKey) throws Exception {
		return doBlind(input, info, serverPublicKey, suite.randomScalar());
	}

	private BlindEvaluateResult doBlindEvaluate(byte[] serverSecretKey, ECPoint blindedElement, byte[] info, ECScalar proofRandomScalar) throws Exception {
		final var skS = suite.decodeScalar(serverSecretKey);
		final var framedInfo = Arrays.concatenate(Labels.INFO, suite.I2OSP(info.length, 2), info);
		final var m = suite.hashToScalar(framedInfo, null, context);
		final var t = suite.getFp().add(skS, m);
		if (!suite.getFp().isValid(t))
			throw new IllegalArgumentException("InverseError");

		final var evaluatedElement = blindedElement.multiply(suite.getFp().inverse(t).toBigInteger());
		final var tweakedKey = suite.getG().multiply(t.toBigInteger());
		final var blindedElements  = new ECPoint[]{ blindedElement };
		final var evaluatedElements = new ECPoint[]{ evaluatedElement };
		final var proof = suite.generateProof(t, suite.getG(), tweakedKey, evaluatedElements, blindedElements, proofRandomScalar, context);
		return new BlindEvaluateResult(evaluatedElement, encodeProof(proof));
	}

	protected BlindEvaluateResult blindEvaluate(byte[] serverSecretKey, ECPoint blindedElement, byte[] info, byte[] proofRandomScalar) throws Exception {
		Objects.requireNonNull(proofRandomScalar, "Mandatory parameter 'proofRandomScalar' missing");
		return doBlindEvaluate(serverSecretKey, blindedElement, info, suite.decodeScalar(proofRandomScalar));
	}

	public BlindEvaluateResult blindEvaluate(byte[] serverSecretKey, ECPoint blindedElement, byte[] info) throws Exception {
		return doBlindEvaluate(serverSecretKey, blindedElement, info, null);
	}

	public byte[] finalize(byte[] input, ECScalar blind, ECPoint evaluatedElement, ECPoint blindedElement, Proof proof, byte[] info, ECPoint tweakedKey) throws Exception {
		final var blindedElements = new ECPoint[]{ blindedElement };
		final var evaluatedElements = new ECPoint[]{ evaluatedElement };
		if (!suite.verifyProof(suite.getG(), tweakedKey, evaluatedElements, blindedElements, proof, context))
			throw new Exception("Failed to verify proof");

		final var invBlind = suite.invertScalar(blind);
		final var n = evaluatedElement.multiply(invBlind.toBigInteger());
		final var unblindedElement = suite.encodeElement(n);
		return suite.hash(Arrays.concatenate(new byte[][]{
			suite.I2OSP(input.length, 2), input,
			suite.I2OSP(info.length, 2), info,
			suite.I2OSP(unblindedElement.length, 2), unblindedElement,
			Labels.FINALIZE
		}));
	}

	public byte[] evaluate(byte[] serverSecretKey, byte[] input, byte[] info) throws Exception {
		final var inputElement = suite.hashToGroup(input, null, context);
		if (!inputElement.isValid() || inputElement.isInfinity())
			throw new IllegalArgumentException("InvalidInputError");

		final var skS = suite.decodeScalar(serverSecretKey);
		final var framedInfo = Arrays.concatenate(Labels.INFO, suite.I2OSP(info.length, 2), info);
		final var m = suite.hashToScalar(framedInfo, null, context);
		final var t = suite.getFp().add(skS, m);
		if (!suite.getFp().isValid(t))
			throw new IllegalArgumentException("InverseError");

		final var evaluatedElement = inputElement.multiply(suite.invertScalar(t).toBigInteger());
		final var issuedElement = suite.encodeElement(evaluatedElement);

		return suite.hash(Arrays.concatenate(new byte[][]{
			suite.I2OSP(input.length, 2), input,
			suite.I2OSP(info.length, 2), info,
			suite.I2OSP(issuedElement.length, 2), issuedElement,
			Labels.FINALIZE
		}));
	}
}
