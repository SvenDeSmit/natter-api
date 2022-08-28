package sven.apisec.manningbook.natterapi.token;

import java.text.ParseException;
import java.util.Date;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import spark.Request;

public class SignedJwtTokenStore implements AuthenticatedTokenStore {

	private static final Logger logger = LoggerFactory.getLogger(SignedJwtTokenStore.class); 
	
	private final JWSSigner signer;
	private final JWSVerifier verifier;
	private final JWSAlgorithm algorithm;
	private final String audience;
	

	
	public SignedJwtTokenStore(JWSSigner signer, JWSVerifier verifier, JWSAlgorithm algorithm, String audience) {
		super();
		this.signer = signer;
		this.verifier = verifier;
		this.algorithm = algorithm;
		this.audience = audience;
	}

	@Override
	public String create(Request request, Token token) {
		logger.info(String.format("Creating JWT token for user %s:", token.username));			

		var claimSet = new JWTClaimsSet.Builder().subject(token.username).audience(audience).expirationTime(Date.from(token.expiry)).claim("attrs", token.attributes).build();
		var header = new JWSHeader(JWSAlgorithm.HS256);
		var jwt = new SignedJWT(header,claimSet);
		logger.info(String.format("JWT token created for user %s: %s", token.username, jwt));			
		try {
			logger.info(String.format("Signing JWT token ...: %s", signer));			

			jwt.sign(signer);
			logger.info(String.format("JWT token signed for user %s", token.username));			
			var tokenstr = jwt.serialize();
			logger.info(String.format("JWT token string created for user %s: %s", token.username, tokenstr));			
			return tokenstr;
		} catch(JOSEException e) {
			logger.info("JWT token creation failure: " + e.getMessage());		
			e.printStackTrace();
			
			throw new RuntimeException(e);
		} catch(Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}
	}

	@Override
	public Optional<Token> read(Request request, String tokenId) {
		try {
			logger.info(String.format("Validating JWT token ..."));			

			var jwt = SignedJWT.parse(tokenId);
			logger.info(String.format("JWT token parsed: %s ...",jwt));			

			
			if (!jwt.verify(verifier)) {
				throw new JOSEException("Invalid signature");
			}
			logger.info(String.format("JWT token has valid signature"));			
			
			var claims = jwt.getJWTClaimsSet();
			if(!claims.getAudience().contains(audience)) {
				throw new JOSEException("Incorrect audience");
			}
			
			var expiry = claims.getExpirationTime().toInstant();
			var subject = claims.getSubject();
			
			var token = new Token(expiry, subject);
			var attrs= claims.getJSONObjectClaim("attrs");
			attrs.forEach((key,value) -> token.attributes.put(key, (String)value));
			logger.info(String.format("JWT token successfully validated for user %s ...",subject));			
			
			return Optional.of(token);
		} catch(ParseException | JOSEException e) {
			return Optional.empty();
		}
	}

	@Override
	public void revoke(Request request, String tokenId) {
		// TODO Auto-generated method stub

	}

}
