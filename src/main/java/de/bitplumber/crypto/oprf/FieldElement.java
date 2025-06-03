package de.bitplumber.crypto.oprf;

public interface FieldElement {
	public FieldElement add(FieldElement other);
	public FieldElement subtract(FieldElement other);
	public FieldElement multiply(FieldElement other);
	public FieldElement invert();
	public byte[] toByteArray();
}
