package de.bitplumber.crypto.oprf;

public interface GroupElement {
	public GroupElement add(GroupElement other);
	public GroupElement subtract(GroupElement other);
	public GroupElement multiply(FieldElement scalar);
	public byte[] toByteArray();
}
