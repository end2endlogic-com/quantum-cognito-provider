package auth;

import com.e2eq.framework.model.persistent.morphia.CredentialRepo;
import com.e2eq.framework.model.security.auth.AuthProviderFactory;
import com.e2eq.framework.model.security.auth.UserManagement;
import com.e2eq.framework.rest.models.AuthRequest;
import com.e2eq.framework.rest.models.AuthResponse;
import com.e2eq.framework.util.TestUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.logging.Log;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;
import org.checkerframework.checker.units.qual.C;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.Matchers.equalTo;


@QuarkusTest
public class TestCognitoRestEndPoints {

    @ConfigProperty(name = "auth.provider")
    String authProvider;

    @Inject
    TestUtils testUtils;

    @ConfigProperty(name = "test.userId")
    String testUserId;

    @ConfigProperty(name = "test.password")
    String testPassword;

    @Inject
    CredentialRepo credentialRepo;

    @Inject
    AuthProviderFactory authProviderFactory;

    @Test
    public void testAdminLogin() throws JsonProcessingException {
        if (authProvider.equals("cognito")) {

            // ensure the credentials exist in cognito and credential database
            UserManagement userManager = authProviderFactory.getUserManager();

            if( !userManager.userIdExists(testUtils.getTestRealm(), testUserId) ) {
                throw new RuntimeException(String.format("Test userId:%s does not exist in cognito or credential database in realm:%s", testUserId, testUtils.getTestRealm()));
            }


            AuthRequest request = new AuthRequest();
            request.setUserId(testUserId);
            request.setPassword(testPassword);
            ObjectMapper mapper = new ObjectMapper();
            String value = mapper.writeValueAsString(request);

         AuthResponse response = given()
                 .contentType(ContentType.JSON)
                 .header("X-Realm", testUtils.getTestRealm())
                 .body(value)
                 .when()
                 .post("/security/login")
                 .then()
                 .statusCode(Response.Status.OK.getStatusCode())
                 .body("access_token", notNullValue())
                 .body("refresh_token", notNullValue())
                 .extract()
                 .as(AuthResponse.class);
         String accessToken = response.getAccess_token();

         Log.info("Access Token: " + accessToken);

         Log.info("===== Attempting to call /test/secure/hello ======");

         // Test admin access
         given()
                 .header("Authorization", "Bearer " + accessToken)
                 .header("X-Realm", testUtils.getTestRealm())
                 .when()
                 .get("/test/secure/hello")
                 .then()
                 .statusCode(200);
        } else {
            Log.info("Test skipped for auth provider: " + authProvider);
        }
    }

    @Test
    public void testUserLogin() throws JsonProcessingException {
        if (authProvider.equals("cognito")) {
            AuthRequest request = new AuthRequest();
            request.setUserId(testUserId);
            request.setPassword(testPassword);
            ObjectMapper mapper = new ObjectMapper();
            String value = mapper.writeValueAsString(request);

            AuthResponse response = given()
                                       .contentType(ContentType.JSON)
                                       .queryParam("realm", testUtils.getTestRealm()) // login take realm as parameter
                                       .body(value)
                                       .when()
                                       .post("/security/login")
                                       .then()
                                       .statusCode(Response.Status.OK.getStatusCode())
                                       .body("access_token", notNullValue())
                                       .body("refresh_token", notNullValue())
                                       .extract()
                                       .as(AuthResponse.class);
            /*   .get("/secure/view")
                    .then()
                    .statusCode(200)
                    .body("message", equalTo("Secure content viewed")); */

            // Test user cannot access admin endpoint
            given()
                    .header("Authorization", "Bearer " + response.getAccess_token())
                    .when()
                    .post("/secure/create")
                    .then()
                    .statusCode(403);


            given()
               .header("Authorization", "Bearer " + response.getAccess_token())
               .when()
               .get("/secure/authenticated")
               .then()
               .statusCode(200);

        } else {
            Log.info("Test skipped for auth provider: " + authProvider);
        }
    }

    @Test
    public void testPublicAccess() {
        given()
                .when()
                .get("/secure/public")
                .then()
                .statusCode(200)
                .body("message", equalTo("Public content"));
    }

    @Test
    public void testInvalidToken() {
        given()
                .header("Authorization", "Bearer invalid-token")
                .when()
                .get("/secure/view")
                .then()
                .statusCode(401);
    }
}
