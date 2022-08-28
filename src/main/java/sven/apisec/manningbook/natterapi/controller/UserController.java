package sven.apisec.manningbook.natterapi.controller;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.dalesbred.Database;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.lambdaworks.crypto.SCryptUtil;

import spark.Filter;
import spark.Request;
import spark.Response;
import static spark.Spark.*;

public class UserController {
	
	private static final Logger logger = LoggerFactory.getLogger(UserController.class); 

	private static final String USERNAME_PATTERN = "[a-zA-Z][a-zA-Z0-9]{1,29}";
	
	private final Database database;
	
	public UserController(Database database) {
		this.database = database;				
	}
	
	public JSONObject registerUser(Request request, Response response) throws Exception {
		var json = new JSONObject(request.body());
		var username = json.getString("username");
		var password = json.getString("password");
		logger.info("Registering user "+username);
		
		if (!username.matches(USERNAME_PATTERN)) {
			throw new IllegalArgumentException("invalid username");
		}
		
		if (password.length() < 8) {
			throw new IllegalArgumentException("password must be at least 8 characters");
		}
		
		var hash = SCryptUtil.scrypt(password, 32768, 8, 1);
		logger.info("Hash: "+hash);
		database.updateUnique("INSERT INTO users(user_id,pw_hash) VALUES(?,?)",username, hash);
		
		response.status(201);
		response.header("Location", "/users/" + username);
		
		return new JSONObject().put("username", username);
	}
	
	public void authenticate(Request request, Response response) {
		var authHeader = request.headers("Authorization");
		logger.info("Authenticating ... "+authHeader);
		if (authHeader == null || !authHeader.startsWith("Basic ")) {
			return;
		}
		
		var offset = "Basic ".length();
		var credentials = new String(Base64.getDecoder().decode(authHeader.substring(offset)),StandardCharsets.UTF_8);
		
		var components = credentials.split(":",2);
		if (components.length != 2) {
			throw new IllegalArgumentException("invalid auth header");
		}
		
		var username = components[0];
		var password = components[1];
		logger.info("User = "+username);
		logger.info("Password = "+password);
		
		if (!username.matches(USERNAME_PATTERN)) {
			throw new IllegalArgumentException("invalid username");
		}
		
		var hash = database.findOptional(String.class, "SELECT pw_hash FROM users WHERE user_id = ?",username);
		
		if (hash.isPresent() && SCryptUtil.check(password, hash.get())) {
			request.attribute("subject", username);
			logger.info("Subject added to session context: "+username);			
		} else {
			logger.info("Authentication failed for user: "+username);			
			
		}
	}
	
	public void requireAuthentication(Request request, Response response) {
		logger.info("Checking if user is authenticated ... "+request.attribute("subject"));			
		if(request.attribute("subject") == null) {
			response.header("WWW-authenticate", "Bearer");
			logger.warn("User is not authenticated");			
			halt(401); // Unauthorized (actually not authenticated)
		}
		logger.info(String.format("User %s was authenticated", request.attribute("subject").toString()));			
	}
	
	public Filter requirePermissions(String method,String permission) {
		logger.info("Creating a permisions filter ...");			
		return (request,response) -> {
			if(!method.equals(request.requestMethod())) {
				return;
			}
			
			requireAuthentication(request, response);
			
			var spaceId = Long.parseLong(request.params(":SpaceId"));
			var username = (String) request.attribute("subject"); 
			
			var perms = database.findOptional(String.class, "SELECT perms FROM permissions WHERE space_id = ? AND user_id = ?",spaceId,username).orElse("");

			logger.info(String.format("User %s has %s permissions for space with id %s", username, perms, spaceId));
			if(!perms.contains(permission)) {
				logger.info(String.format("User %s has no %s access for space with id %s", username, permission,spaceId));
				halt(403); // Forbidden
			} else {
				logger.info(String.format("User %s has %s access for space with id %s", username, permission, spaceId));
			}
		};
	}
	
}
