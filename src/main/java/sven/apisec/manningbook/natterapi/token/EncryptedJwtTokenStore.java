package sven.apisec.manningbook.natterapi.token;

import java.text.ParseException;
import java.util.Date;
import java.util.Optional;
import java.util.Set;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

import spark.Request;

public class EncryptedJwtTokenStore implements SecureTokenStore {

	private static final Logger logger = LoggerFactory.getLogger(EncryptedJwtTokenStore.class); 
	
	private final SecretKey encKey;
	private final DatabaseTokenStore tokenWhiteListStore;
	

	public EncryptedJwtTokenStore(SecretKey encKey, DatabaseTokenStore tokenWhiteListStore) {
		this.encKey = encKey;
		this.tokenWhiteListStore = tokenWhiteListStore;
	}

	@Override
	public String create(Request request, Token token) {
		logger.info(String.format("Creating JWT token for user %s:", token.username));	
		
		var jwtId = tokenWhiteListStore.create(request, token);
		logger.info(String.format("JWT token stored in whitelist table for user %s with ID: %s", token.username, jwtId));	
		
		var claimsBuilder = new JWTClaimsSet.Builder().subject(token.username).audience("https://localhost:4567").expirationTime(Date.from(token.expiry)).jwtID(jwtId);
		token.attributes.forEach(claimsBuilder::claim);
		
		var header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);
		var jwt = new EncryptedJWT(header, claimsBuilder.build());
		logger.info(String.format("JWT token created for user %s: %s", token.username, jwt));			

		try {
			var encrypter = new DirectEncrypter(encKey);
			logger.info(String.format("Encrypting JWT token ...: %s", encrypter));			
			jwt.encrypt(encrypter);
			logger.info(String.format("JWT token encrypted for user %s", token.username));						
			var tokenStr = jwt.serialize();
			logger.info(String.format("JWT token string created for user %s: %s", token.username, tokenStr));			
			return tokenStr;

		} catch (JOSEException e) {
			logger.info("JWT token creation failure: " + e.getMessage());		
			e.printStackTrace();
			throw new RuntimeException(e);
		}
	}

	@Override
	public Optional<Token> read(Request request, String tokenId) {
		try {
			logger.info(String.format("Validating JWT token ..."));			

			var jwt = EncryptedJWT.parse(tokenId);
			logger.info(String.format("JWT token parsed: %s ...",jwt.serialize()));			
			
			var decrypter = new DirectDecrypter(encKey);
			jwt.decrypt(decrypter);
			logger.info(String.format("JWT token decrypted: %s",jwt.serialize()));			

			
			var claims = jwt.getJWTClaimsSet();
			if(!claims.getAudience().contains("https://localhost:4567")) {
				return Optional.empty();				
			}
			
			var expiry = claims.getExpirationTime().toInstant();
			var subject = claims.getSubject();
			
			var jwtId = claims.getJWTID();
			var tokenFromStore = tokenWhiteListStore.read(request, jwtId);
			if (tokenFromStore.isEmpty()) {
				logger.info(String.format("JWT token is NOT in whitelist table : %s",jwtId));			
				return Optional.empty();
			} 
			logger.info(String.format("JWT token is in whitelist table : %s",jwtId));			

			
			var token = new Token(expiry, subject);
			var ignore = Set.of("exp","sub","aud");
			for (var attr : claims.getClaims().keySet()) {
				if (ignore.contains(attr)) continue;
				token.attributes.put(attr, claims.getStringClaim(attr));
			}
			logger.info(String.format("JWT token successfully decrypted for user %s ...: %s",subject,token));			
			
			return Optional.of(token);
		} catch (ParseException | JOSEException e) {
			logger.info("JWT token reading failure: " + e.getMessage());		
			e.printStackTrace();
			throw new RuntimeException(e);
			
		}
	}

	@Override
	public void revoke(Request request, String tokenId) {
		logger.info(String.format("Revoking JWT token ..."));			
		
		try {
			var jwt = EncryptedJWT.parse(tokenId);
			logger.info(String.format("JWT token parsed: %s ...",jwt.serialize()));			
			
			var decrypter = new DirectDecrypter(encKey);
			jwt.decrypt(decrypter);
			logger.info(String.format("JWT token decrypted: %s",jwt.serialize()));			

			
			var claims = jwt.getJWTClaimsSet();
			if(!claims.getAudience().contains("https://localhost:4567")) {
				logger.info("Audience not matching in JWT token: ");		
				return;				
			}
			
			var jwtId = claims.getJWTID();
			tokenWhiteListStore.read(request, jwtId);
			logger.info(String.format("JWT token is revoked from the whitelist table : %s",jwtId));						
		} catch (ParseException | JOSEException e) {
			logger.info("JWT token reading failure: " + e.getMessage());		
			e.printStackTrace();
			throw new RuntimeException(e);
			
		}
		 

	}

}
