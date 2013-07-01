var rng;

function do_init() {
  rng = new SecureRandom();
}

function pick_rand(N) {
  var n = new BigInteger(N);
  var n1 = n.subtract(BigInteger.ONE);
  var r = new BigInteger(n.bitLength(), rng);
  return r.mod(n1).add(BigInteger.ONE);
}

function getSecCurve() {
  return getSECCurveByName("secp128r1");
}

function get_curve() {
  var c = getSecCurve();
  return new ECCurveFp(new BigInteger(c.getCurve().getQ().toString()),
    new BigInteger(c.getCurve().getA().toBigInteger().toString()),
    new BigInteger(c.getCurve().getB().toBigInteger().toString()));
}

function generate() {
  var c = getSecCurve();
  var r = pick_rand(c.getN().toString());
  $('#privgenkey').val(r.toString());
  generate_public(c, '#pubgenkey', '#privgenkey', '#pubcomp');
  return false;
}

function generateRecv() {
  var c = getSecCurve();
  var r = pick_rand(c.getN().toString());
  $('#recvPrivKey').val(r.toString());
  generate_public(c, '#recvPubKey', '#recvPrivKey', '#recvcomp');
  return false;
}

function encrypt() {
  if($('#privgenkey').val().trim().length == 0) {
    alert("Please enter a private key first");
    return false;
  }
  if($('#recvPubKey').val().trim().length == 0) {
    alert("Please enter the recipients public key first");
    return false;
  }
  var curve = get_curve();
  
  var pubkey = $('#recvPubKey').val().split(",");
  var pubx = pubkey[0];  
  var puby = pubkey[1]; 
  var priv = $('#privgenkey').val(); 
  
  var P = new ECPointFp(curve,
    curve.fromBigInteger(new BigInteger(pubx)),
    curve.fromBigInteger(new BigInteger(puby)));
  var a = new BigInteger(priv);
  var S = P.multiply(a);
  
  $('#enc-sharedkey').val(S.getX().toBigInteger().toString() + ","
    + S.getY().toBigInteger().toString());
    
  var password = S.getX().toBigInteger().toString();
  var plaintext = $('#message').val();
  $('#enc-message').val( Aes.Ctr.encrypt(plaintext, password, 256));
  $('#dec-message').val( Aes.Ctr.encrypt(plaintext, password, 256));
  return false;
}

function decrypt() {
  if($('#recvPrivKey').val().trim().length == 0) {
    alert("Please enter recipients private key first");
    return;
  }
  if($('#pubgenkey').val().trim().length == 0) {
    alert("Please enter a public key of the originator first");
    return;
  }
  
  var privkey = $('#recvPrivKey').val();
  var pubkey = $('#pubgenkey').val().split(",");
  var pubx = pubkey[0];  
  var puby = pubkey[1]; 
  
  var curve = get_curve();
  var P = new ECPointFp(curve,
    curve.fromBigInteger(new BigInteger(pubx)),
    curve.fromBigInteger(new BigInteger(puby)));
  var a = new BigInteger(privkey);
  var S = P.multiply(a);
  
  $('#dec-sharedkey').val(S.getX().toBigInteger().toString() + ","
    + S.getY().toBigInteger().toString());
    
  var password = S.getX().toBigInteger().toString();
  var ciphertext = $('#dec-message').val();
  $('#result').val(Aes.Ctr.decrypt(ciphertext, password, 256));
  return false;
}

function bytesToHex(bytes) {
  			for (var hex = [], i = 0; i < bytes.length; i++) {
					hex.push((bytes[i] >>> 4).toString(16));
					hex.push((bytes[i] & 0xF).toString(16));
				}
				return hex.join("");
			}


function generate_public(c, pubEle, privEle, compEle) {
  var curve = new ECCurveFp(new BigInteger(c.getCurve().getQ().toString()),
    new BigInteger(c.getCurve().getA().toBigInteger().toString()),
    new BigInteger(c.getCurve().getB().toBigInteger().toString()));
  
  var G = new ECPointFp(curve,
    curve.fromBigInteger(new BigInteger(c.getG().getX().toBigInteger().toString())),
    curve.fromBigInteger(new BigInteger(c.getG().getY().toBigInteger().toString())));
  
  
  var a = new BigInteger($(privEle).val());
  var P = G.multiply(a);
  
  var pubx = P.getX().toBigInteger().toString();
  var puby = P.getY().toBigInteger().toString();
  
  $(pubEle).val(pubx + "," + puby);
  
  var hexcomp = bytesToHex(P.getEncoded(true)).toString().toUpperCase();
  P = curve.decodePointHex(hexcomp);
  pubx = P.getX().toBigInteger().toString();
  puby = P.getY().toBigInteger().toString();
  
  $(compEle).val(hexcomp + ' ' + pubx + "," + puby);
  
}
