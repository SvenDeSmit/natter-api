package sven.apisec.manningbook.natterapi;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.dalesbred.Database;
import org.dalesbred.DatabaseSQLException;
import org.dalesbred.result.EmptyResultException;
import org.h2.jdbc.JdbcSQLException;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.JSONException;
import org.json.JSONObject;

import com.google.common.util.concurrent.RateLimiter;

import spark.Request;
import spark.Response;
import spark.Spark;

import static spark.Spark.*;

import sven.apisec.manningbook.natterapi.controller.AuditController;
import sven.apisec.manningbook.natterapi.controller.SpaceController;
import sven.apisec.manningbook.natterapi.controller.TokenController;
import sven.apisec.manningbook.natterapi.controller.UserController;
import sven.apisec.manningbook.natterapi.token.CookieTokenStore;
import sven.apisec.manningbook.natterapi.token.DummyTokenStore;

public class Main2 {
	
	public static void main(String...args) throws Exception {
		var datasource = JdbcConnectionPool.create("jdbc:h2:mem:natter","natter","password");
		var database = Database.forDataSource(datasource);
		createTables(database);
		
		// USE DB USER with limited GRANTS
		datasource = JdbcConnectionPool.create("jdbc:h2:mem:natter","natter_api_user","password");
		database = Database.forDataSource(datasource);
		
		secure("natterserver.p12","changeit",null,null);
		
		Spark.staticFiles.location("/public");
		Spark.port(4568);
		
		var tokenController = new TokenController(new CookieTokenStore());
		post("/sessions",tokenController::login);
		delete("/sessions",tokenController::logout);
		
				
		var spaceController = new SpaceController(database);
		post("/spaces/:spaceId/members", spaceController::addMember);
		post("/spaces/:spaceId/messages", spaceController::addMessage);
		get("/spaces/:spaceId/messages/:msgId", spaceController::readMessageById);
		
		post("/spaces", spaceController::createSpace);

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
		
		before(userController::authenticate);
		before(tokenController::validateToken);
		
		before(auditController::auditRequestStart);
		
		before("/sessions",userController::requireAuthentication);
		
		before("/spaces",userController::requireAuthentication);
		before("/spaces/:spaceId/members",userController::requireAuthentication);
		before("/spaces/:spaceId/messages",userController.requirePermissions("POST","w"));
		before("/spaces/:spaceId/messages/:msgId",userController.requirePermissions("GET","r"));
		
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
		
		exception(IllegalArgumentException.class, Main2::badRequest);
		exception(DatabaseSQLException.class, Main2::badWrappedRequest);
		exception(JSONException.class, Main2::badRequest);
		exception(EmptyResultException.class, (e,request,response) -> response.status(404));
	}
	
	private static void createTables(Database database) throws Exception {
		var path = Paths.get(Main2.class.getResource("/schema.sql").toURI());
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
