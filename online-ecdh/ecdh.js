var ECDH = {}; // ECDH namespace.
var rng = new SecureRandom();

/**
 * Encrypt a message using ECDH
 * http://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman
 *
 * @param private_key The senders private key.
 * @param public_key The receivers compressed public key.
 * @param message The string we want to encrypt.
 * @returns The message encrypted
 */
ECDH.encrypt = function(private_key, public_key, plaintext) {
  var curve = this.get_curve();
  
  var P = curve.decodePointHex(public_key);
  pubx = P.getX().toBigInteger().toString();
  puby = P.getY().toBigInteger().toString();
  
  var a = new BigInteger(private_key);
  var S = P.multiply(a);
    
  var password = S.getX().toBigInteger().toString();
  return Aes.Ctr.encrypt(plaintext, password, 256);
} 

/**
 * Decrypt a message using ECDH
 *
 * @param private_key The receivers private key.
 * @param public_key The senders public key.
 * @param ciphertext The string we want to decrypt.
 * @returns The message decrypted
 */
ECDH.decrypt = function(private_key, public_key, ciphertext) {

  var curve = this.get_curve();
  var P = curve.decodePointHex(public_key);
  var a = new BigInteger(private_key);
  var S = P.multiply(a);
    
  var password = S.getX().toBigInteger().toString();
  return Aes.Ctr.decrypt(ciphertext, password, 256);
} 

/**
 * Given a private key get the compressed public key
 *
 * @param private_key The receivers private key.
 * @returns A compressed public key.
 */
ECDH.compressed_public = function(private_key) {
  var c = this.getSecCurve();
  var curve = new ECCurveFp(
    new BigInteger(c.getCurve().getQ().toString()),
    new BigInteger(c.getCurve().getA().toBigInteger().toString()),
    new BigInteger(c.getCurve().getB().toBigInteger().toString()));
  
  var G = new ECPointFp(curve,
    curve.fromBigInteger(
      new BigInteger(c.getG().getX().toBigInteger().toString())),
    curve.fromBigInteger(
      new BigInteger(c.getG().getY().toBigInteger().toString())));
  
  
  var a = new BigInteger(private_key);
  var P = G.multiply(a);
  
  var hexcomp = this.bytesToHex(
    P.getEncoded(true)).toString().toUpperCase();
  
  return hexcomp;
} 

/**
 * Creates a random private key
 *
 * @returns A completely random private key.
 */
ECDH.generate_private_key = function() {
  var c = this.getSecCurve();
  var r = this.pick_rand(c.getN().toString());
  return r;
}

/*
 * ---- remaining routines are private, not called externally ----
 */
ECDH.bytesToHex = function(bytes) {
  for (var hex = [], i = 0; i < bytes.length; i++) {
    hex.push((bytes[i] >>> 4).toString(16));
    hex.push((bytes[i] & 0xF).toString(16));
  }
  return hex.join("");
}
      
ECDH.pick_rand = function(N) {
  var n = new BigInteger(N);
  var n1 = n.subtract(BigInteger.ONE);
  var r = new BigInteger(n.bitLength(), rng);
  return r.mod(n1).add(BigInteger.ONE);
}

ECDH.getSecCurve = function() {
  return getSECCurveByName("secp128r1");
}

ECDH.get_curve = function() {
  var c = this.getSecCurve();
  return new ECCurveFp(new BigInteger(c.getCurve().getQ().toString()),
    new BigInteger(c.getCurve().getA().toBigInteger().toString()),
    new BigInteger(c.getCurve().getB().toBigInteger().toString()));
}
