package sven.apisec.manningbook.natterapi;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.Set;
import java.util.logging.LogManager;

import javax.crypto.SecretKey;

import org.dalesbred.Database;
import org.dalesbred.DatabaseSQLException;
import org.dalesbred.result.EmptyResultException;
import org.h2.jdbc.JdbcSQLException;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.util.concurrent.RateLimiter;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;

import software.pando.crypto.nacl.SecretBox;
import spark.Request;
import spark.Response;
import spark.Spark;

import static spark.Spark.*;

import sven.apisec.manningbook.natterapi.controller.AuditController;
import sven.apisec.manningbook.natterapi.controller.SpaceController;
import sven.apisec.manningbook.natterapi.controller.TokenController;
import sven.apisec.manningbook.natterapi.controller.UserController;
import sven.apisec.manningbook.natterapi.token.CookieTokenStore;
import sven.apisec.manningbook.natterapi.token.DatabaseTokenStore;
import sven.apisec.manningbook.natterapi.token.DummyTokenStore;
import sven.apisec.manningbook.natterapi.token.EncryptedJwtTokenStore;
import sven.apisec.manningbook.natterapi.token.EncryptedTokenStore;
import sven.apisec.manningbook.natterapi.token.HmacTokenStore;
import sven.apisec.manningbook.natterapi.token.JsonTokenStore;
import sven.apisec.manningbook.natterapi.token.SecureTokenStore;
import sven.apisec.manningbook.natterapi.token.SignedJwtTokenStore;
import sven.apisec.manningbook.natterapi.token.TokenStore;

public class Main {

	private static final Logger logger = LoggerFactory.getLogger(Main.class); 


	public static void main(String...args) throws Exception {
		
		var datasource = JdbcConnectionPool.create("jdbc:h2:mem:natter","natter","password");
		var database = Database.forDataSource(datasource);
		createTables(database);
		
		// USE DB USER with limited GRANTS
		datasource = JdbcConnectionPool.create("jdbc:h2:mem:natter","natter_api_user","password");
		database = Database.forDataSource(datasource);
		
		secure("natterserver.p12","changeit",null,null);
		
		Spark.staticFiles.location("/public");
		
		//var tokenController = new TokenController(new DatabaseTokenStore(database));
		
		var keyPassword = System.getProperty("keystore.password", "changeit").toCharArray();
		var keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(new FileInputStream("natterserver.p12"),keyPassword);
		logger.info("KeyStore object: "+keyStore.containsAlias("hmac-key2"));
		
		SecretKey macKey = (SecretKey)keyStore.getKey("hmac-key2", keyPassword);
		logger.info("MAC key object: "+macKey);

		SecretKey aesKey = (SecretKey)keyStore.getKey("aes-key", keyPassword);
		logger.info("EAS key object: "+macKey);

		//TokenStore tokenStore = new DatabaseTokenStore(database);
		
		/*
		TokenStore tokenStore = new JsonTokenStore(); 
		tokenStore = new HmacTokenStore(tokenStore, macKey);
		var tokenController = new TokenController(tokenStore);
		*/
		
		/*
		var algorithm = JWSAlgorithm.HS256;
		var signer = new MACSigner(macKey);
		var verifier = new MACVerifier(macKey);
		TokenStore tokenStore = new SignedJwtTokenStore(signer, verifier, algorithm, "https://localhost:4567");
		var tokenController = new TokenController(tokenStore);
		*/

		/*
		var naclKey = SecretBox.key(aesKey.getEncoded());
		TokenStore tokenStore = new JsonTokenStore();		
		tokenStore = new EncryptedTokenStore(tokenStore, naclKey);
		var tokenController = new TokenController(tokenStore);
		*/

		DatabaseTokenStore dbTokenStore = new DatabaseTokenStore(database);
		SecureTokenStore tokenStore = new EncryptedJwtTokenStore(aesKey,dbTokenStore);
		var tokenController = new TokenController(tokenStore);
		var spaceController = new SpaceController(database);
		var userController = new UserController(database);

		post("/users", userController::registerUser);
		var auditController = new AuditController(database);
		get("/logs",auditController::readAuditLog);
		
		var rateLimiter = RateLimiter.create(1.0d);

		before((request,response) -> {
			if (!rateLimiter.tryAcquire()) {
					halt(429);
			}
		});
		
		before(new CORSFilter(Set.of("https://localhost:4568")));
		
		before(userController::authenticate);
		before(tokenController::validateToken);
		
		before(auditController::auditRequestStart);
		
		before("/sessions",userController::requireAuthentication);
		before("/sessions",tokenController.requireScope("POST","full_access"));
		post("/sessions",tokenController::login);
		delete("/sessions",tokenController::logout);

		
		before("/spaces",userController::requireAuthentication);
		before("/spaces",tokenController.requireScope("POST","create_space"));
		post("/spaces", spaceController::createSpace);

		before("/spaces/*/messages",tokenController.requireScope("POST","post_message"));
		before("/spaces/:spaceId/messages",userController.requirePermissions("POST","w"));
		post("/spaces/:spaceId/messages", spaceController::addMessage);
		
		
		before("/spaces/*/messages/*",tokenController.requireScope("GET","read_message"));
		before("/spaces/:spaceId/messages/:msgId",userController.requirePermissions("GET","r"));
		get("/spaces/:spaceId/messages/:msgId", spaceController::readMessageById);
		
		before("/spaces/*/messages",tokenController.requireScope("GET","list_messages"));
		before("/spaces/:spaceId/messages",userController.requirePermissions("GET","r"));
		get("/spaces/:spaceId/messages", spaceController::findMessages);
		
		before("/spaces/*/messages/*",tokenController.requireScope("DELETE","delete_message"));
		before("/spaces/:spaceId/messages/:msgId",userController.requirePermissions("DELETE","d"));
		delete("/spaces/:spaceId/messages/:msgId", spaceController::deleteMessage);
		
		
		
		//before("/spaces/:spaceId/members",userController::requireAuthentication);
		
		before("/spaces/*/members",tokenController.requireScope("POST","add_member"));
		before("/spaces/:spaceId/messages",userController.requirePermissions("POST","rwd"));
		post("/spaces/:spaceId/members", spaceController::addMember);
		

		
		before((request,response) -> {
			if (request.requestMethod().equals("POST") && !"application/json".equals(request.contentType())) {
					halt(415, new JSONObject().put("error", "Only application/json supported").toString());
			}
		});
						
		afterAfter((request,response) -> {
			response.type("application/json; charset=utf-8");
			response.header("X-Content-Type-Options", "nosniff");
			response.header("X-Frame-Options", "deny");
			response.header("X-XSS-Protection", "1; mode=block");
			response.header("Cache-Control", "private, max-age=0");
			response.header("Content-Security-Policy","default-src 'none'; frame-ancestors 'none'; sandbox");
			response.header("Server", "");
			//response.header("Strict-Transport_security","max-age=31536000");
		});
		
		afterAfter(auditController::auditRequestEnd);
		
		
		internalServerError(new JSONObject().put("error", "internal server error").toString());
		notFound(new JSONObject().put("error","not found").toString());
		
		exception(IllegalArgumentException.class, Main::badRequest);
		exception(DatabaseSQLException.class, Main::badWrappedRequest);
		exception(JSONException.class, Main::badRequest);
		exception(EmptyResultException.class, (e,request,response) -> response.status(404));
	}
	
	private static void createTables(Database database) throws Exception {
		var path = Paths.get(Main.class.getResource("/schema.sql").toURI());
		database.update(Files.readString(path));
	}
	
	private static void badRequest(Exception ex,Request request, Response response) {
		response.status(400);
		//response.body("{\"error\": \"" + ex + "\"}");
		// don't include class names
		response.body("{\"error\": \"" + ex.getMessage() + "\"}");
		
	}
	private static void badWrappedRequest(Exception ex,Request request, Response response) {
		response.status(400);
		response.body("{\"error\": \"" + ex.getCause().getMessage() + "\"}");
		
	}

}
