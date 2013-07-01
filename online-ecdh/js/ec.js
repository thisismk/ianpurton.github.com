// Basic Javascript Elliptic Curve implementation
// Ported loosely from BouncyCastle's Java EC code
// Only Fp curves implemented for now

// Requires jsbn.js and jsbn2.js

// ----------------
// ECFieldElementFp

// constructor
function ECFieldElementFp(q,x) {
    this.x = x;
    // TODO if(x.compareTo(q) >= 0) error
    this.q = q;
}

function feFpEquals(other) {
    if(other == this) return true;
    return (this.q.equals(other.q) && this.x.equals(other.x));
}

function feFpToBigInteger() {
    return this.x;
}

function feFpNegate() {
    return new ECFieldElementFp(this.q, this.x.negate().mod(this.q));
}

function feFpAdd(b) {
    return new ECFieldElementFp(this.q, this.x.add(b.toBigInteger()).mod(this.q));
}

function feFpSubtract(b) {
    return new ECFieldElementFp(this.q, this.x.subtract(b.toBigInteger()).mod(this.q));
}

function feFpMultiply(b) {
    return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger()).mod(this.q));
}

function feFpSquare() {
    return new ECFieldElementFp(this.q, this.x.square().mod(this.q));
}

function feFpDivide(b) {
    return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger().modInverse(this.q)).mod(this.q));
}

function sqrt() {
  		if (!this.q.testBit(0)) throw new Error("even value of q");

			// p mod 4 == 3
			if (this.q.testBit(1)) {
				// z = g^(u+1) + p, p = 4u + 3
				var z = new ECFieldElementFp(this.q, this.x.modPow(this.q.shiftRight(2).add(BigInteger.ONE), this.q));
				return z.square().equals(this) ? z : null;
			}

			// p mod 4 == 1
			var qMinusOne = this.q.subtract(BigInteger.ONE);
			var legendreExponent = qMinusOne.shiftRight(1);
			if (!(this.x.modPow(legendreExponent, this.q).equals(BigInteger.ONE))) return null;
			var u = qMinusOne.shiftRight(2);
			var k = u.shiftLeft(1).add(BigInteger.ONE);
			var Q = this.x;
			var fourQ = Q.shiftLeft(2).mod(this.q);
			var U, V;

			do {
				var rand = new SecureRandom();
				var P;
				do {
					P = new BigInteger(this.q.bitLength(), rand);
				}
				while (P.compareTo(this.q) >= 0 || !(P.multiply(P).subtract(fourQ).modPow(legendreExponent, this.q).equals(qMinusOne)));

				var result = ec.FieldElementFp.fastLucasSequence(this.q, P, Q, k);

				U = result[0];
				V = result[1];
				if (V.multiply(V).mod(this.q).equals(fourQ)) {
					// Integer division by 2, mod q
					if (V.testBit(0)) {
						V = V.add(this.q);
					}
					V = V.shiftRight(1);
					return new ec.FieldElementFp(this.q, V);
				}
			}
			while (U.equals(BigInteger.ONE) || U.equals(qMinusOne));

			return null;
		};

		/*
		* Copyright (c) 2000 - 2011 The Legion Of The Bouncy Castle (http://www.bouncycastle.org)
		* Ported to JavaScript by bitaddress.org
		*/
		function fastLucasSequence (p, P, Q, k) {
			// TODO Research and apply "common-multiplicand multiplication here"

			var n = k.bitLength();
			var s = k.getLowestSetBit();
			var Uh = BigInteger.ONE;
			var Vl = BigInteger.TWO;
			var Vh = P;
			var Ql = BigInteger.ONE;
			var Qh = BigInteger.ONE;

			for (var j = n - 1; j >= s + 1; --j) {
				Ql = Ql.multiply(Qh).mod(p);
				if (k.testBit(j)) {
					Qh = Ql.multiply(Q).mod(p);
					Uh = Uh.multiply(Vh).mod(p);
					Vl = Vh.multiply(Vl).subtract(P.multiply(Ql)).mod(p);
					Vh = Vh.multiply(Vh).subtract(Qh.shiftLeft(1)).mod(p);
				}
				else {
					Qh = Ql;
					Uh = Uh.multiply(Vl).subtract(Ql).mod(p);
					Vh = Vh.multiply(Vl).subtract(P.multiply(Ql)).mod(p);
					Vl = Vl.multiply(Vl).subtract(Ql.shiftLeft(1)).mod(p);
				}
			}

			Ql = Ql.multiply(Qh).mod(p);
			Qh = Ql.multiply(Q).mod(p);
			Uh = Uh.multiply(Vl).subtract(Ql).mod(p);
			Vl = Vh.multiply(Vl).subtract(P.multiply(Ql)).mod(p);
			Ql = Ql.multiply(Qh).mod(p);

			for (var j = 1; j <= s; ++j) {
				Uh = Uh.multiply(Vl).mod(p);
				Vl = Vl.multiply(Vl).subtract(Ql.shiftLeft(1)).mod(p);
				Ql = Ql.multiply(Ql).mod(p);
			}

			return [Uh, Vl];
		};


ECFieldElementFp.prototype.equals = feFpEquals;
ECFieldElementFp.prototype.toBigInteger = feFpToBigInteger;
ECFieldElementFp.prototype.negate = feFpNegate;
ECFieldElementFp.prototype.add = feFpAdd;
ECFieldElementFp.prototype.subtract = feFpSubtract;
ECFieldElementFp.prototype.multiply = feFpMultiply;
ECFieldElementFp.prototype.square = feFpSquare;
ECFieldElementFp.prototype.divide = feFpDivide;
ECFieldElementFp.prototype.sqrt = sqrt;
ECFieldElementFp.prototype.fastLucasSequence  = fastLucasSequence ;

// ----------------
// ECPointFp

// constructor
function ECPointFp(curve,x,y,z) {
    this.curve = curve;
    this.x = x;
    this.y = y;
    // Projective coordinates: either zinv == null or z * zinv == 1
    // z and zinv are just BigIntegers, not fieldElements
    if(z == null) {
      this.z = BigInteger.ONE;
    }
    else {
      this.z = z;
    }
    this.zinv = null;
    //TODO: compression flag
}

function pointFpGetX() {
    if(this.zinv == null) {
      this.zinv = this.z.modInverse(this.curve.q);
    }
    return this.curve.fromBigInteger(this.x.toBigInteger().multiply(this.zinv).mod(this.curve.q));
}

function pointFpGetY() {
    if(this.zinv == null) {
      this.zinv = this.z.modInverse(this.curve.q);
    }
    return this.curve.fromBigInteger(this.y.toBigInteger().multiply(this.zinv).mod(this.curve.q));
}

function pointFpEquals(other) {
    if(other == this) return true;
    if(this.isInfinity()) return other.isInfinity();
    if(other.isInfinity()) return this.isInfinity();
    var u, v;
    // u = Y2 * Z1 - Y1 * Z2
    u = other.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(other.z)).mod(this.curve.q);
    if(!u.equals(BigInteger.ZERO)) return false;
    // v = X2 * Z1 - X1 * Z2
    v = other.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(other.z)).mod(this.curve.q);
    return v.equals(BigInteger.ZERO);
}

function pointFpIsInfinity() {
    if((this.x == null) && (this.y == null)) return true;
    return this.z.equals(BigInteger.ZERO) && !this.y.toBigInteger().equals(BigInteger.ZERO);
}

function pointFpNegate() {
    return new ECPointFp(this.curve, this.x, this.y.negate(), this.z);
}

function pointFpAdd(b) {
    if(this.isInfinity()) return b;
    if(b.isInfinity()) return this;

    // u = Y2 * Z1 - Y1 * Z2
    var u = b.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(b.z)).mod(this.curve.q);
    // v = X2 * Z1 - X1 * Z2
    var v = b.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(b.z)).mod(this.curve.q);

    if(BigInteger.ZERO.equals(v)) {
        if(BigInteger.ZERO.equals(u)) {
            return this.twice(); // this == b, so double
        }
	return this.curve.getInfinity(); // this = -b, so infinity
    }

    var THREE = new BigInteger("3");
    var x1 = this.x.toBigInteger();
    var y1 = this.y.toBigInteger();
    var x2 = b.x.toBigInteger();
    var y2 = b.y.toBigInteger();

    var v2 = v.square();
    var v3 = v2.multiply(v);
    var x1v2 = x1.multiply(v2);
    var zu2 = u.square().multiply(this.z);

    // x3 = v * (z2 * (z1 * u^2 - 2 * x1 * v^2) - v^3)
    var x3 = zu2.subtract(x1v2.shiftLeft(1)).multiply(b.z).subtract(v3).multiply(v).mod(this.curve.q);
    // y3 = z2 * (3 * x1 * u * v^2 - y1 * v^3 - z1 * u^3) + u * v^3
    var y3 = x1v2.multiply(THREE).multiply(u).subtract(y1.multiply(v3)).subtract(zu2.multiply(u)).multiply(b.z).add(u.multiply(v3)).mod(this.curve.q);
    // z3 = v^3 * z1 * z2
    var z3 = v3.multiply(this.z).multiply(b.z).mod(this.curve.q);

    return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
}

function pointFpTwice() {
    if(this.isInfinity()) return this;
    if(this.y.toBigInteger().signum() == 0) return this.curve.getInfinity();

    // TODO: optimized handling of constants
    var THREE = new BigInteger("3");
    var x1 = this.x.toBigInteger();
    var y1 = this.y.toBigInteger();

    var y1z1 = y1.multiply(this.z);
    var y1sqz1 = y1z1.multiply(y1).mod(this.curve.q);
    var a = this.curve.a.toBigInteger();

    // w = 3 * x1^2 + a * z1^2
    var w = x1.square().multiply(THREE);
    if(!BigInteger.ZERO.equals(a)) {
      w = w.add(this.z.square().multiply(a));
    }
    w = w.mod(this.curve.q);
    // x3 = 2 * y1 * z1 * (w^2 - 8 * x1 * y1^2 * z1)
    var x3 = w.square().subtract(x1.shiftLeft(3).multiply(y1sqz1)).shiftLeft(1).multiply(y1z1).mod(this.curve.q);
    // y3 = 4 * y1^2 * z1 * (3 * w * x1 - 2 * y1^2 * z1) - w^3
    var y3 = w.multiply(THREE).multiply(x1).subtract(y1sqz1.shiftLeft(1)).shiftLeft(2).multiply(y1sqz1).subtract(w.square().multiply(w)).mod(this.curve.q);
    // z3 = 8 * (y1 * z1)^3
    var z3 = y1z1.square().multiply(y1z1).shiftLeft(3).mod(this.curve.q);

    return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
}

// Simple NAF (Non-Adjacent Form) multiplication algorithm
// TODO: modularize the multiplication algorithm
function pointFpMultiply(k) {
    if(this.isInfinity()) return this;
    if(k.signum() == 0) return this.curve.getInfinity();

    var e = k;
    var h = e.multiply(new BigInteger("3"));

    var neg = this.negate();
    var R = this;

    var i;
    for(i = h.bitLength() - 2; i > 0; --i) {
	R = R.twice();

	var hBit = h.testBit(i);
	var eBit = e.testBit(i);

	if (hBit != eBit) {
	    R = R.add(hBit ? this : neg);
	}
    }

    return R;
}

// Compute this*j + x*k (simultaneous multiplication)
function pointFpMultiplyTwo(j,x,k) {
  var i;
  if(j.bitLength() > k.bitLength())
    i = j.bitLength() - 1;
  else
    i = k.bitLength() - 1;

  var R = this.curve.getInfinity();
  var both = this.add(x);
  while(i >= 0) {
    R = R.twice();
    if(j.testBit(i)) {
      if(k.testBit(i)) {
        R = R.add(both);
      }
      else {
        R = R.add(this);
      }
    }
    else {
      if(k.testBit(i)) {
        R = R.add(x);
      }
    }
    --i;
  }

  return R;
}

function getEncoded (compressed) {
			var x = this.getX().toBigInteger();
			var y = this.getY().toBigInteger();
			var len = 32; // integerToBytes will zero pad if integer is less than 32 bytes. 32 bytes length is required by the Bitcoin protocol.
			var enc = x.toByteArrayUnsigned();

			// when compressed prepend byte depending if y point is even or odd 
			if (compressed) {
				if (y.isEven()) {
					enc.unshift(0x02);
				}
				else {
					enc.unshift(0x03);
				}
			}
			else {
				enc.unshift(0x04);
				enc = enc.concat(this.integerToBytes(y, len)); // uncompressed public key appends the bytes of the y point
			}
			return enc;
		};
    

ECPointFp.prototype.getX = pointFpGetX;
ECPointFp.prototype.getY = pointFpGetY;
ECPointFp.prototype.equals = pointFpEquals;
ECPointFp.prototype.isInfinity = pointFpIsInfinity;
ECPointFp.prototype.negate = pointFpNegate;
ECPointFp.prototype.add = pointFpAdd;
ECPointFp.prototype.twice = pointFpTwice;
ECPointFp.prototype.multiply = pointFpMultiply;
ECPointFp.prototype.multiplyTwo = pointFpMultiplyTwo;
ECPointFp.prototype.getEncoded = getEncoded;

// ----------------
// ECCurveFp

// constructor
function ECCurveFp(q,a,b) {
    this.q = q;
    this.a = this.fromBigInteger(a);
    this.b = this.fromBigInteger(b);
    this.infinity = new ECPointFp(this, null, null);
}

function curveFpGetQ() {
    return this.q;
}

function curveFpGetA() {
    return this.a;
}

function curveFpGetB() {
    return this.b;
}

function curveFpEquals(other) {
    if(other == this) return true;
    return(this.q.equals(other.q) && this.a.equals(other.a) && this.b.equals(other.b));
}

function curveFpGetInfinity() {
    return this.infinity;
}

function curveFpFromBigInteger(x) {
    return new ECFieldElementFp(this.q, x);
}

// for now, work with hex strings because they're easier in JS
function curveFpDecodePointHex(s) {
			var firstByte = parseInt(s.substr(0, 2), 16);

    switch(firstByte) { // first byte
    case 0:
	return this.infinity;
    case 2:// compressed
    case 3:// compressed
					var yTilde = firstByte & 1;
					var xHex = s.substr(2, s.length - 2);
					var X1 = new BigInteger(xHex, 16);
					return this.decompressPoint(yTilde, X1);

	return null;
    case 4:
    case 6:
    case 7:
	var len = (s.length - 2) / 2;
	var xHex = s.substr(2, len);
	var yHex = s.substr(len+2, len);

	return new ECPointFp(this,
			     this.fromBigInteger(new BigInteger(xHex, 16)),
			     this.fromBigInteger(new BigInteger(yHex, 16)));

    default: // unsupported
	return null;
    }
}


function decompressPoint(yTilde, X1) {
			var x = this.fromBigInteger(X1);
			var alpha = x.multiply(x.square().add(this.getA())).add(this.getB());
			var beta = alpha.sqrt();
			// if we can't find a sqrt we haven't got a point on the curve - run!
			if (beta == null) throw new Error("Invalid point compression");
			var betaValue = beta.toBigInteger();
			var bit0 = betaValue.testBit(0) ? 1 : 0;
			if (bit0 != yTilde) {
				// Use the other root
				beta = this.fromBigInteger(this.getQ().subtract(betaValue));
			}
			return new ECPointFp(this, x, beta, null, true);
		};


function fromHex() { return new BigInteger(s, 16); };



ECCurveFp.prototype.getQ = curveFpGetQ;
ECCurveFp.prototype.getA = curveFpGetA;
ECCurveFp.prototype.getB = curveFpGetB;
ECCurveFp.prototype.equals = curveFpEquals;
ECCurveFp.prototype.getInfinity = curveFpGetInfinity;
ECCurveFp.prototype.fromBigInteger = curveFpFromBigInteger;
ECCurveFp.prototype.decodePointHex = curveFpDecodePointHex;
ECCurveFp.prototype.decompressPoint = decompressPoint;
ECCurveFp.prototype.fromHex = fromHex;
