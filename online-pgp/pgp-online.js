function encrypt() {
    openpgp.init();
    var pub_key = openpgp.read_publicKey($('#pubkey').text());
    $('#message').val(openpgp.write_encrypted_message(pub_key,$('#message').val()));
    return false;
}

function generate() {
    openpgp.init();
    var keys = openpgp.generate_key_pair(1, 512, 'Test McTestington <test@example.com>', '');
    $('#privgenkey').val(keys.privateKeyArmored);
  	$('#pubgenkey').val(keys.publicKeyArmored);
    return false;
}

function decrypt() {
    openpgp.init();
    var priv_key = openpgp.read_privateKey($('#dec-privkey').text());
    var msg = openpgp.read_message($('#dec-message').text());
    
    var keymat = null;
		var sesskey = null;
		// Find the private (sub)key for the session key of the message
		for (var i = 0; i< msg[0].sessionKeys.length; i++) {
			if (priv_key[0].privateKeyPacket.publicKey.getKeyId() == msg[0].sessionKeys[i].keyId.bytes) {
				keymat = { key: priv_key[0], keymaterial: priv_key[0].privateKeyPacket};
				sesskey = msg[0].sessionKeys[i];
				break;
			}
			for (var j = 0; j < priv_key[0].subKeys.length; j++) {
				if (priv_key[0].subKeys[j].publicKey.getKeyId() == msg[0].sessionKeys[i].keyId.bytes) {
					keymat = { key: priv_key[0], keymaterial: priv_key[0].subKeys[j]};
					sesskey = msg[0].sessionKeys[i];
					break;
				}
			}
		}
		if (keymat != null) {
			if (!keymat.keymaterial.decryptSecretMPIs('')) {
				alert("Password for secrect key was incorrect!");
				return;

			}
			$('#dec-message').text(msg[0].decrypt(keymat, sesskey));
		} else {
			alert("No private key found!");
		}
    
    return false;
}


