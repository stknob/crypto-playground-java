package de.bitplumber.crypto.oprf;

public interface Oprf<S, E, BR> {
	public KeyPair deriveKeypair(byte[] seed, byte[] info) throws Exception;
	public KeyPair randomKeypair();

	public byte[] encodeElement(E element);
	public E decodeElement(byte[] input) throws Exception;

	public byte[] encodeScalar(S scalar);
	public S decodeScalar(byte[] input);
	public S randomScalar();

	public BR blind(byte[] input);
	public E blindEvaluate(byte[] secretKey, E blindedElement);
	public byte[] finalize(byte[] input, S blind, E evaluatedElement);
	public byte[] evaluate(byte[] secretKey, byte[] input);
}
