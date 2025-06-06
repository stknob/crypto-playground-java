package de.bitplumber.crypto.oprf;

public interface Oprf<S, E, BR> {
	public KeyPair deriveKeyPair(byte[] seed, byte[] info) throws Exception;
	public KeyPair randomKeyPair();

	public byte[] encodeElement(E element);
	public E decodeElement(byte[] input) throws Exception;

	public byte[] encodeScalar(S scalar);
	public S decodeScalar(byte[] input) throws Exception;
	public S randomScalar();

	public BR blind(byte[] input) throws Exception;
	public E blindEvaluate(byte[] serverSecretKey, E blindedElement) throws Exception;
	public byte[] finalize(byte[] input, S blind, E evaluatedElement) throws Exception;
	public byte[] evaluate(byte[] serverSecretKey, byte[] input) throws Exception;
}
