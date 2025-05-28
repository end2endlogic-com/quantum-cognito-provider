package auth;

import com.e2eq.framework.model.security.auth.AuthProvider;
import com.e2eq.framework.rest.models.AuthRequest;
import com.e2eq.framework.rest.models.AuthResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.logging.Log;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.Matchers.equalTo;


@QuarkusTest
public class TestCognitoRestEndPoints {

    @ConfigProperty(name = "auth.provider")
    String authProvider;

    @ConfigProperty(name = "test.userId")
    String testUserId;

    @ConfigProperty(name = "test.password")
    String testPassword;

    @Test
    public void testAdminLogin() throws JsonProcessingException {
        if (authProvider.equals("cognito")) {

            AuthRequest request = new AuthRequest();
            request.setUserId(testUserId);
            request.setPassword(testPassword);
            ObjectMapper mapper = new ObjectMapper();
            String value = mapper.writeValueAsString(request);

         AuthResponse response = given()
                 .contentType(ContentType.JSON)
                 .body(value)
                 .when()
                 .post("/security/login")
                 .then()
                 .statusCode(Response.Status.OK.getStatusCode())
                 .body("access_token", notNullValue())
                 .body("refresh_token", notNullValue())
                 .extract()
                 .as(AuthResponse.class);

         Log.info("Access Token: " + response.getAccess_token());

         // Test admin access
         given()
                 .header("Authorization", "Bearer " + response.getAccess_token())
                 .when()
                 .post("/secure/create")
                 .then()
                 .statusCode(200)
                 .body("message", equalTo("Secure content created"));
        } else {
            Log.info("Test skipped for auth provider: " + authProvider);
        }
    }

    @Test
    public void testUserLogin() {
        if (authProvider.equals("cognito")) {
            AuthProvider.LoginPositiveResponse response = given()
                    .contentType(ContentType.JSON)
                    .queryParam("userId", testUserId)
                    .queryParam("password", testPassword)
                    .when()
                    .post("/auth/login")
                    .then()
                    .statusCode(200)
                    .body("accessToken", notNullValue())
                    .body("refreshToken", notNullValue())
                    .extract()
                    .as(AuthProvider.LoginPositiveResponse.class);

            // Test user access to view
            given()
                    .header("Authorization", "Bearer " + response.accessToken())
                    .when()
                    .get("/secure/view")
                    .then()
                    .statusCode(200)
                    .body("message", equalTo("Secure content viewed"));

            // Test user cannot access admin endpoint
            given()
                    .header("Authorization", "Bearer " + response.accessToken())
                    .when()
                    .post("/secure/create")
                    .then()
                    .statusCode(403);
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
