package auth;

import com.e2eq.framework.exceptions.ReferentialIntegrityViolationException;
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

import java.util.Set;

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
         Assert.assertFalse(userManager.userExists("system@system.com"));

         userManager.createUser("system@system.com", "T35t$!Movista", Set.of("user", "admin"), domainContext);
      }
   }

   @Test
   public void testCreateCognitoUser() throws ReferentialIntegrityViolationException {
      if (authProvider.equals("cognito")) {

         AuthProvider authProvider = authProviderFactory.getAuthProvider();
         UserManagement userManager = authProviderFactory.getUserManager();

         try (final SecuritySession s = new SecuritySession(pContext, rContext)) {
            DomainContext domainContext = DomainContext.builder()
                                             .orgRefName(testUtils.getTestOrgRefName())
                                             .defaultRealm(testUtils.getTestRealm())
                                             .accountId(testUtils.getTestAccountNumber())
                                             .tenantId(testUtils.getTestTenantId())
                                             .build();


            userManager.removeUser(testUserId);
            Assert.assertFalse(userManager.userExists(testUserId));

            userManager.createUser(testUserId, testPassword, Set.of("user","admin"), domainContext);

            Set<String> roles = userManager.getUserRoles(testUserId);
            Assert.assertTrue(roles.contains("user"));
            AuthProvider.LoginResponse response = authProvider.login(testUserId, testPassword);
            Assert.assertTrue(response.authenticated());
            Assert.assertTrue(userManager.userExists(testUserId));
            userManager.assignRoles(testUserId, Set.of("admin"));
            Assert.assertTrue(userManager.getUserRoles(testUserId).contains("admin"));
            userManager.removeRoles(testUserId, Set.of("admin", "user"));
            Assert.assertFalse(userManager.getUserRoles(testUserId).contains("admin"));
            //userManager.removeUser(testUserId);
            //Assert.assertFalse(userManager.userExists(testUserId));
         }
      } else {
         Log.infof("Test skipped for auth provider: {%s}", authProvider);
      }
   }
}
