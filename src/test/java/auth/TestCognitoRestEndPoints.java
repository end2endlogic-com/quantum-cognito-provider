package auth;

import com.e2eq.framework.exceptions.ReferentialIntegrityViolationException;
import com.e2eq.framework.model.persistent.base.DataDomain;
import com.e2eq.framework.model.persistent.migration.base.MigrationService;
import com.e2eq.framework.model.persistent.morphia.CredentialRepo;
import com.e2eq.framework.model.persistent.morphia.UserProfileRepo;
import com.e2eq.framework.model.persistent.security.CredentialUserIdPassword;
import com.e2eq.framework.model.persistent.security.DomainContext;
import com.e2eq.framework.model.persistent.security.UserProfile;
import com.e2eq.framework.model.security.auth.AuthProviderFactory;
import com.e2eq.framework.model.security.auth.UserManagement;
import com.e2eq.framework.model.securityrules.SecuritySession;
import com.e2eq.framework.rest.exceptions.DatabaseMigrationException;
import com.e2eq.framework.rest.models.AuthRequest;
import com.e2eq.framework.rest.models.AuthResponse;
import com.e2eq.framework.util.EncryptionUtils;
import com.e2eq.framework.util.TestUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.logging.Log;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.smallrye.mutiny.Multi;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;
import org.checkerframework.checker.units.qual.C;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static com.ibm.icu.impl.Assert.fail;
import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.Matchers.equalTo;


@QuarkusTest
public class TestCognitoRestEndPoints extends BaseRepoTest{

    @ConfigProperty(name = "auth.provider")
    String authProvider;

    @Inject
    TestUtils testUtils;

    @ConfigProperty(name = "quantum.realmConfig.testUserId")
    String testUserId;


    @ConfigProperty(name = "test.password")
    String testPassword;

    @Inject
    CredentialRepo credentialRepo;

    @Inject
    AuthProviderFactory authProviderFactory;

    @Inject
    MigrationService migrationService;


    public void ensureTestUserExists() throws ReferentialIntegrityViolationException {
            UserManagement userManager = authProviderFactory.getUserManager();
            if (!userManager.userIdExists(testUserId)) {
                DataDomain dataDomain = new DataDomain();
                dataDomain.setOrgRefName(testUtils.getTestOrgRefName());
                dataDomain.setAccountNum(testUtils.getTestAccountNumber());
                dataDomain.setTenantId(testUtils.getTestTenantId());
                dataDomain.setOwnerId(testUtils.getTestUserId());
                userManager.createUser(testUserId, testPassword, Set.of("user"), new DomainContext(dataDomain, testUtils.getTestRealm()));
            }
        }

   public void ensureMigrated() {
        try {
            migrationService.checkInitialized(testUtils.getSystemRealm());
        } catch (DatabaseMigrationException ex) {

           Multi.createFrom().emitter(emitter -> {
              migrationService.runAllUnRunMigrations(testUtils.getSystemRealm(), emitter);
              migrationService.runAllUnRunMigrations(testUtils.getDefaultRealm(), emitter);
              migrationService.runAllUnRunMigrations(testUtils.getTestRealm(), emitter);
           }).subscribe().with(
              item -> System.out.println("Emitting: " + item),
              failure ->fail("Failed with: " + failure)
           );
        }
   }



    @Test
    public void testAdminLogin() throws JsonProcessingException, ReferentialIntegrityViolationException {
        if (authProvider.equals("cognito")) {
           try(final SecuritySession ignored = new SecuritySession(pContext, rContext)) {
              ensureMigrated();
              ensureTestUserExists();
           }


            // ensure the credentials exist in cognito and credential database
            UserManagement userManager = authProviderFactory.getUserManager();

            if( !userManager.userIdExists(testUtils.getTestRealm(), testUserId) ) {
               // create the user in cognito
                userManager.createUser(testUtils.getTestRealm(), testUserId, testPassword, Boolean.FALSE,  Set.of("user"), DomainContext.builder()
                                                                                                           .accountId(testUtils.getTestAccountNumber())
                                                                                                           .orgRefName(testUtils.getTestOrgRefName())
                                                                                                           .defaultRealm(testUtils.getTestRealm())
                                                                                                           .tenantId(testUtils.getTestTenantId()).build());
            }


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
           try(final SecuritySession ignored = new SecuritySession(pContext, rContext)) {
              ensureMigrated();
           }

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
