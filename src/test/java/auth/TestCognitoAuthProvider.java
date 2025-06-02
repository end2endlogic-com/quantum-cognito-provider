package auth;

import com.e2eq.framework.exceptions.ReferentialIntegrityViolationException;
import com.e2eq.framework.model.persistent.morphia.CredentialRepo;
import com.e2eq.framework.model.persistent.morphia.UserProfileRepo;
import com.e2eq.framework.model.persistent.security.CredentialUserIdPassword;
import com.e2eq.framework.model.persistent.security.DomainContext;
import com.e2eq.framework.model.security.auth.AuthProvider;
import com.e2eq.framework.model.security.auth.AuthProviderFactory;
import com.e2eq.framework.model.security.auth.UserManagement;
import com.e2eq.framework.model.securityrules.SecuritySession;
import com.e2eq.framework.util.TestUtils;
import io.quarkus.logging.Log;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.Test;
import org.wildfly.common.Assert;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@QuarkusTest
public class TestCognitoAuthProvider extends BaseRepoTest{
   @ConfigProperty(name = "auth.provider")
   String authProvider;

   @Inject
   AuthProviderFactory authProviderFactory;

   @ConfigProperty(name = "test.userId")
   String testUserId;

   @ConfigProperty(name = "test.password")
   String testPassword;

   @Inject
   TestUtils testUtils;
   @Inject
   CredentialRepo credentialRepo;

   @Inject
   UserProfileRepo userProfileRepo;



   @Test
   public void testCreateSystemUser() throws ReferentialIntegrityViolationException {
      AuthProvider authProvider = authProviderFactory.getAuthProvider();
      UserManagement userManager = authProviderFactory.getUserManager();

      try (final SecuritySession s = new SecuritySession(pContext, rContext)) {
         DomainContext domainContext = DomainContext.builder()
                                          .orgRefName("system")
                                          .defaultRealm("system-com")
                                          .accountId("00000002")
                                          .tenantId("system-com")
                                          .build();

         userManager.removeUser("system@system.com");
         Assert.assertFalse(userManager.userIdExists("system@system.com"));

         userManager.createUser("system@system.com", "T35t$!Movista", "system@system.com", Set.of("user", "admin"), domainContext);
      }
   }

   //@Test
   public void testGetRoles() {
      if (authProvider.equals("cognito")) {
         UserManagement userManager = authProviderFactory.getUserManager();
         Set<String> roles = userManager.getUserRoles("56d9c248-982c-4080-9817-ffe09d39ecc9" );
         Assert.assertTrue(roles.contains("user"));
      }
   }

   @Test
   public void testCreateCognitoUser() throws ReferentialIntegrityViolationException {
      if (authProvider.equals("cognito")) {

         // ensure the user is created in the database


         AuthProvider authProvider = authProviderFactory.getAuthProvider();
         UserManagement userManager = authProviderFactory.getUserManager();

         try (final SecuritySession s = new SecuritySession(pContext, rContext)) {
            DomainContext domainContext = DomainContext.builder()
                                             .orgRefName(testUtils.getTestOrgRefName())
                                             .defaultRealm(testUtils.getTestRealm())
                                             .accountId(testUtils.getTestAccountNumber())
                                             .tenantId(testUtils.getTestTenantId())
                                             .build();

            Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUserId(testUserId);
            if (ocred.isPresent()) {
               credentialRepo.delete(ocred.get());
               if (!userManager.removeUser(ocred.get().getUsername())) {
                  throw new IllegalStateException(String.format("User not removed in cognito usr name:%s with userid:%s in credentials collection in  realm: %s may be stale", ocred.get().getUsername(),ocred.get().getUserId(), credentialRepo.getDatabaseName()));
               }
               boolean removed = userManager.removeUser(ocred.get().getUsername());
               if (!removed) {
                  Log.warnf("User not removed could not find userName:% in credentials collection in  realm: %s: ", ocred.get().getUsername(), credentialRepo.getDatabaseName());
               }
               credentialRepo.delete(ocred.get());
            } else {
               Assert.assertFalse(userManager.userIdExists(testUserId));
               String username = UUID.randomUUID().toString();
               userManager.createUser(testUserId, testPassword, UUID.randomUUID().toString(), Set.of("user", "admin"), domainContext);
               Assert.assertTrue(userManager.usernameExists(username));

               Set<String> roles = userManager.getUserRoles(username);
               Assert.assertTrue(roles.contains("user"));
               AuthProvider.LoginResponse response = authProvider.login(testUserId, testPassword);
               Assert.assertTrue(response.authenticated());
               Assert.assertTrue(userManager.userIdExists(testUserId));
               userManager.assignRoles(testUserId, Set.of("admin"));
               Assert.assertTrue(userManager.getUserRoles(testUserId).contains("admin"));
               userManager.removeRoles(testUserId, Set.of("admin", "user"));
               Assert.assertFalse(userManager.getUserRoles(testUserId).contains("admin"));
               //userManager.removeUser(testUserId);
               //Assert.assertFalse(userManager.userExists(testUserId));
            }
         }
      } else {
         Log.infof("Test skipped for auth provider: {%s}", authProvider);
      }
   }
}
