

import java.math.BigInteger;
import java.util.Objects;

/**
 * The point class defines the points on the Elliptic curve (Ed448-Goldilocks)
 * 
 * @authors Lindsay Ding, Alan Thompson, Christopher Henderson
 *
 */
public class Point {
	
	public static final BigInteger
		p = (BigInteger.TWO.pow(448).subtract(BigInteger.TWO.pow(224))).subtract(BigInteger.ONE);

	public static final BigInteger 
		r = BigInteger.TWO.pow(446).
		subtract(new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));

	public static final BigInteger d = BigInteger.valueOf(-39081);
    
	public static final Point G = new Point(BigInteger.valueOf(8), Point.p, false);
	
    /**
     * Number values of Points
     */
    private final BigInteger x, y;

    /**
     * Neutral element constructor
     */
    public Point() {
        this.x = BigInteger.ZERO;
        this.y = BigInteger.ONE;
    }

    /**
     * Constructor for a curve point with given x and y coordinates
     * @param x x-coordinate
     * @param y y-coordinate
     */
    public Point(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }


    /**
     * Constructor for a curve point from its x coordinate and the least significant bit of y
     * @param x x-coordinate
     * @param p the given modulus
     * @param lsb the least significant bit of y
     */
    public Point(BigInteger x, BigInteger p, boolean lsb) {
        this.x = x;
        BigInteger numerator = BigInteger.ONE.subtract(x.pow(2));
        BigInteger denominator = BigInteger.ONE.subtract(d.multiply(x.pow(2))); // 1 + 39801 * x^2, d = -39801
        BigInteger v = numerator.multiply(denominator.modInverse(p)).mod(p);
        this.y = sqrt(v, p, lsb);
    }

    /**
     * Gets the X coordinate of this point. 
     * @return BigInteger: X
     */
    public BigInteger getX() {
    	return x;
    }
    
    /**
     * Gets the Y coordinate of this point. 
     * @return BigInteger: Y
     */
    public BigInteger getY() {
    	return y;
    }
    
    /**
     * Gets the bytes of the X coordinate of this point. 
     * @return byte array containing the two's-complement representation 
     */
    public byte[] getXBytes() {
    	return x.toByteArray();
    }
    
    /**
     * Gets the bytes of the Y coordinate of this point. 
     * @return byte array containing the two's-complement representation 
     */
    public byte[] getYBytes() {
    	return y.toByteArray();
    }
    
    /**
     * Gets the number of bytes used by the X coordinate of this point. 
     * @return number of bytes
     */
    public int getXLength() {
    	return x.toByteArray().length;
    }
    
    /**
     * Gets the number of bytes used by the Y coordinate of this point. 
     * @return long: number of bytes
     */
    public int getYLength() {
    	return y.toByteArray().length;
    }
    
    /**
     * Gets the number of bytes used by this point. 
     * @return long: number of bytes
     */
    public long getByteSize() {
    	return x.toByteArray().length + y.toByteArray().length;
    }

    /**
     * Get a curve point's x-coordinate mod p
     * @return the value after modulus in bytes
     */
    public byte[] modPtoBytes() {
        BigInteger coordinate = this.getX();
        return (coordinate.mod(p)).toByteArray();
    }

    /**
     * Compute a square root of v mod p with a specified least significant bit, if such a root exists.
     * Reference: Appendix A of project description
     * @param v the radicand.
     * @param p the modulus (must satisfy p mod 4 = 3).
     * @param lsb desired least significant bit (true: 1, false: 0).
     * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
     * if such a root exists, otherwise null.
     */
    public BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    /**
     * Obtain the opposite point of the current point.
     * @return the opposite point (p - x, y).
     */
    public Point opposite() {
        BigInteger xCoor = p.subtract(x);
        return new Point(xCoor, this.y);
    }


    /**
     * Compute the sum of current point and a given point.
     * @param pt a specified point on the curve.
     * @return a new point on the curve which is the sum of the two points.
     */
    public Point sum(Point pt) {

        BigInteger factor = this.x.multiply(this.y).multiply(pt.x).multiply(pt.y);
        BigInteger nX = (this.x.multiply(pt.y)).add(this.y.multiply(pt.x));
        BigInteger dX = BigInteger.ONE.add(d.multiply(factor));
        BigInteger nY = (this.y.multiply(pt.y)).subtract(this.x.multiply(pt.x));
        BigInteger dY = BigInteger.ONE.subtract(d.multiply(factor));

        BigInteger xCoor = (nX.multiply(dX.modInverse(p))).mod(p);
        BigInteger yCoor = (nY.multiply(dY.modInverse(p))).mod(p);

        return new Point(xCoor, yCoor);
    }

    /**
     * Compare current point with a specified point.
     * 
     * @param otherPoint a specified point on the curve.
     * @return true if the two points are equal otherwise false.
     */
    @Override
    public boolean equals(final Object otherPoint) {
        if (this == otherPoint)
            return true;
        
        if (otherPoint == null ||
        	getClass() != otherPoint.getClass())
            return false;
        
        Point pt = (Point) otherPoint;
        
        if (this.x.compareTo(pt.x) != 0 || 
        	this.y.compareTo(pt.y) != 0)
        	return false;
        else return true;
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return Objects.hash(x, y);
    }
    
    @Override
    /** 
     * String representation of this point's x and y values 
     */
    public String toString() {
        return  "x-> " + this.x + "\n" + "y-> " + this.y;
    }

}
