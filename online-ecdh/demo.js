function generate() {
  var r = ECDH.generate_private_key();
  $('#privgenkey').val(r.toString());
  generate_public('#privgenkey', '#pubcomp');
  return false;
}

function generateRecv() {
  var r = ECDH.generate_private_key();
  $('#recvPrivKey').val(r.toString());
  generate_public('#recvPrivKey', '#recvcomp');
  return false;
}

function encrypt() {
  if($('#privgenkey').val().trim().length == 0) {
    alert("Please enter a private key first");
    return false;
  }
  if($('#recvcomp').val().trim().length == 0) {
    alert("Please enter the recipients public key first");
    return false;
  }
  
  var pubkey = $('#recvcomp').val();
  var priv = $('#privgenkey').val(); 
  var plaintext = $('#message').val();
  
  var encrypted = ECDH.encrypt(priv, pubkey, plaintext);
  
  $('#enc-message').val(encrypted);
  $('#dec-message').val(encrypted);
  
  return false;
}

function decrypt() {
  if($('#recvPrivKey').val().trim().length == 0) {
    alert("Please enter recipients private key first");
    return;
  }
  if($('#pubcomp').val().trim().length == 0) {
    alert("Please enter a public key of the originator first");
    return;
  }
  
  var privkey = $('#recvPrivKey').val();
  var pubkey = $('#pubcomp').val();
  var ciphertext = $('#dec-message').val();
  
  var plaintext = ECDH.decrypt(privkey, pubkey, ciphertext);
  
  $('#result').val(plaintext);
  return false;
}

function generate_public(privEle, compEle) {

  var priv_key = $(privEle).val();
  var hexcomp = ECDH.compressed_public(priv_key);
  $(compEle).val(hexcomp);
  
}
