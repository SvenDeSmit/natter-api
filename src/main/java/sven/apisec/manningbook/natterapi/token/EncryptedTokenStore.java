package sven.apisec.manningbook.natterapi.token;

import java.security.Key;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import software.pando.crypto.nacl.SecretBox;
import spark.Request;

public class EncryptedTokenStore implements SecureTokenStore {

	private static final Logger logger = LoggerFactory.getLogger(EncryptedTokenStore.class); 

	private final TokenStore delegate;
	private final Key encKey;	

	public EncryptedTokenStore(TokenStore delegate, Key encKey) {
		this.delegate = delegate;
		this.encKey = encKey;
	}

	@Override
	public String create(Request request, Token token) {
		var tokenId = delegate.create(request, token);
		logger.info("Encrypting token ID "+tokenId);
		var tokenStr = SecretBox.encrypt(encKey, tokenId).toString();
		logger.info("Encrypted token ID= "+tokenStr);
		return tokenStr;
	}

	@Override
	public Optional<Token> read(Request request, String tokenId) {
		logger.info("Decrypting token ID "+tokenId);	
		var box = SecretBox.fromString(tokenId);
		var decodedTokenID = box.decryptToString(encKey);
		logger.info("Decrypted token ID = "+decodedTokenID);
		return delegate.read(request, decodedTokenID);
	}

	@Override
	public void revoke(Request request, String tokenId) {
		logger.info("Decrypting token ID "+tokenId);	
		var box = SecretBox.fromString(tokenId);
		var decodedTokenID = box.decryptToString(encKey);
		logger.info("Decrypted token ID = "+decodedTokenID);
		delegate.revoke(request, decodedTokenID);
	}

}
