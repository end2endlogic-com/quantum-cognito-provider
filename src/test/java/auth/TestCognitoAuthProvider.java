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
import com.e2eq.framework.util.EncryptionUtils;
import com.e2eq.framework.util.TestUtils;
import io.quarkus.logging.Log;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.Test;
import org.wildfly.common.Assert;

import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.fail;

@QuarkusTest
public class TestCognitoAuthProvider extends BaseRepoTest{
   @ConfigProperty(name = "auth.provider")
   String authProvider;

   @Inject
   AuthProviderFactory authProviderFactory;

   @ConfigProperty(name = "test.userId")
   String testUserId;

   @ConfigProperty(name = "test.username")
   String testUsername;

   @ConfigProperty(name = "test.password")
   String testPassword;

   @Inject
   TestUtils testUtils;
   @Inject
   CredentialRepo credentialRepo;

   @Inject
   UserProfileRepo userProfileRepo;



   @Test
   public void testCreateTestUser() throws ReferentialIntegrityViolationException {
      AuthProvider authProvider = authProviderFactory.getAuthProvider();
      UserManagement userManager = authProviderFactory.getUserManager();

      try (final SecuritySession s = new SecuritySession(pContext, rContext)) {
        if (userManager.usernameExists(testUsername)) {
           userManager.removeUserWithUsername(testUsername);
        }

        assert(!userManager.usernameExists(testUsername));

        if (!userManager.userIdExists(testUserId))
            userManager.createUser(testUserId, testPassword, Boolean.FALSE, testUsername, Set.of("user", "admin"), DomainContext.builder()
                                                                                                    .accountId(testUtils.getTestAccountNumber())
                                                                                                    .defaultRealm(testUtils.getTestRealm())
                                                                                                    .tenantId(testUtils.getTestTenantId())
                                                                                                    .orgRefName(testUtils.getTestOrgRefName())
                                                                                                    .accountId(testUtils.getTestAccountNumber())
                                                                                                    .build());
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
         AuthProvider authProvider = authProviderFactory.getAuthProvider();
         UserManagement userManager = authProviderFactory.getUserManager();

         try (final SecuritySession s = new SecuritySession(pContext, rContext)) {


            Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUserId(testUserId);
            if (ocred.isPresent()) {
               credentialRepo.delete(ocred.get());
               if (!userManager.removeUserWithUsername(ocred.get().getUsername())) {
                  throw new IllegalStateException(String.format("User not removed in cognito usr name:%s with userid:%s in credentials collection in  realm: %s may be stale", ocred.get().getUsername(),ocred.get().getUserId(), credentialRepo.getDatabaseName()));
               }
               boolean removed = userManager.removeUserWithUsername(ocred.get().getUsername());
               if (!removed) {
                  Log.warnf("User not removed could not find userName:%s in credentials collection in  realm: %s: ", ocred.get().getUsername(), credentialRepo.getDatabaseName());
               }
               credentialRepo.delete(ocred.get());
            }
            if (userManager.userIdExists(testUserId)) {
               // user exists in cognito but does exist in the credentials database
               // create it in the credential database
               CredentialUserIdPassword cred = CredentialUserIdPassword.builder()
                                             .userId(testUserId)
                                             .username(testUsername)
                                                  .passwordHash(EncryptionUtils.hashPassword(testPassword))
                                                  .domainContext (
                                                     DomainContext.builder()
                                                          .orgRefName(testUtils.getTestOrgRefName())
                                                          .defaultRealm(testUtils.getTestRealm())
                                                          .accountId(testUtils.getTestAccountNumber())
                                                          .tenantId(testUtils.getTestTenantId())
                                                          .build()
                                                  )
                                                  .roles(Set.of("user", "admin").toArray(new String[2]))
                                                  .lastUpdate(new Date())
                                             .build();
               cred = credentialRepo.save(cred);
            } else {
               DomainContext domainContext = DomainContext.builder()
                                                .orgRefName(testUtils.getTestOrgRefName())
                                                .defaultRealm(testUtils.getTestRealm())
                                                .accountId(testUtils.getTestAccountNumber())
                                                .tenantId(testUtils.getTestTenantId())
                                                .build();
               userManager.createUser(testUserId, testPassword, Boolean.FALSE, testUsername, Set.of("user", "admin"), domainContext);
               Assert.assertTrue(userManager.usernameExists(testUsername));
            }

            Set<String> roles = userManager.getUserRoles(testUsername);
            Assert.assertTrue(roles.contains("user"));
            AuthProvider.LoginResponse response = authProvider.login(testUserId, testPassword);
            Assert.assertTrue(response.authenticated());
            userManager.assignRoles(testUsername, Set.of("admin"));
            Assert.assertTrue(userManager.getUserRoles(testUsername).contains("admin"));
            userManager.removeRoles(testUsername, Set.of("admin", "user"));
            Assert.assertFalse(userManager.getUserRoles(testUsername).contains("admin"));
            //userManager.removeUser(testUserId);
            //Assert.assertFalse(userManager.userExists(testUserId));
         }
      } else {
         Log.infof("Test skipped for auth provider: {%s}", authProvider);
      }
   }
}
