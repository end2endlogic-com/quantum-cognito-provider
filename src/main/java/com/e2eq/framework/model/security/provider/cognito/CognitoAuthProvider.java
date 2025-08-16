package com.e2eq.framework.model.security.provider.cognito;

import com.e2eq.framework.exceptions.ReferentialIntegrityViolationException;
import com.e2eq.framework.model.persistent.morphia.CredentialRepo;
import com.e2eq.framework.model.persistent.morphia.MorphiaUtils;
import com.e2eq.framework.model.persistent.morphia.UserProfileRepo;
import com.e2eq.framework.model.persistent.security.CredentialUserIdPassword;
import com.e2eq.framework.model.persistent.security.DomainContext;
import com.e2eq.framework.model.security.auth.AuthProvider;
import com.e2eq.framework.model.security.auth.UserManagement;

import com.e2eq.framework.model.security.auth.provider.jwtToken.BaseAuthProvider;
import com.e2eq.framework.util.EncryptionUtils;
import com.e2eq.framework.util.SecurityUtils;
import com.e2eq.framework.util.TokenUtils;
import com.e2eq.framework.util.ValidateUtils;
import io.quarkus.logging.Log;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.security.runtime.SecurityIdentityAssociation;
import io.smallrye.common.constraint.Nullable;
import io.smallrye.jwt.auth.principal.JWTParser;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.JsonArray;
import jakarta.json.JsonValue;

import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.WebApplicationException;
import org.apache.commons.lang3.NotImplementedException;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

/**
 * CognitoAuthProvider is an implementation of AuthProvider and UserManagement interfaces.
 * It provides authentication and user management functionalities using AWS Cognito.
 */
@ApplicationScoped
public class CognitoAuthProvider extends BaseAuthProvider implements AuthProvider, UserManagement {

    private boolean isCognitoDisabled() {
        try {
            String up = (userPoolId == null) ? "" : userPoolId.trim();
            String cid = (clientId == null) ? "" : clientId.trim();
            return up.equalsIgnoreCase("ignore") || cid.equalsIgnoreCase("ignore");
        } catch (Exception e) {
            return true;
        }
    }

    private void enhanceLoginPositiveResponse(Object positiveResponse, String realmHint) {
        if (positiveResponse == null) return;
        try {
            // Resolve realm to set
            String resolvedRealm = (realmHint != null && !realmHint.isBlank()) ? realmHint : defaultRealm;

            // Try setRealm(String)
            try {
                java.lang.reflect.Method setRealm = positiveResponse.getClass().getMethod("setRealm", String.class);
                setRealm.invoke(positiveResponse, resolvedRealm);
            } catch (NoSuchMethodException ignored) {
                // ignore if method not present
            }

            // Try setMongodburl(String) and setMongoDbUrl(String) variants
            boolean mongoSet = false;
            try {
                java.lang.reflect.Method setMongodburl = positiveResponse.getClass().getMethod("setMongodburl", String.class);
                setMongodburl.invoke(positiveResponse, mongodbConnectionString);
                mongoSet = true;
            } catch (NoSuchMethodException ignored) {
            }
            if (!mongoSet) {
                try {
                    java.lang.reflect.Method setMongoDbUrl = positiveResponse.getClass().getMethod("setMongoDbUrl", String.class);
                    setMongoDbUrl.invoke(positiveResponse, mongodbConnectionString);
                } catch (NoSuchMethodException ignored) {
                }
            }
        } catch (Exception e) {
            // Do not fail login if enhancement fails, just log
            Log.debug("Could not enhance LoginPositiveResponse with mongodburl/realm: " + e.getMessage());
        }
    }

    @Inject
    CredentialRepo credentialRepo;

    @Inject
    JWTParser jwtParser;

    @Inject
    SecurityIdentityAssociation securityIdentityAssociation;

    @ConfigProperty(
        name = "aws.cognito.user-pool-id",
        defaultValue = "us-west-2_1234567890"
    )
    String userPoolId;

    @ConfigProperty(
        name = "aws.cognito.client-id",
        defaultValue = "1234567890abcdefg"
    )
    String clientId;

    @ConfigProperty(name = "com.b2bi.jwt.duration")
    Long durationInSeconds;

    // Additional configuration for enhancing LoginResponse
    @ConfigProperty(name = "quarkus.mongodb.connection-string", defaultValue = "")
    String mongodbConnectionString;

    @ConfigProperty(name = "quantum.realmConfig.defaultRealm", defaultValue = "system-com")
    String defaultRealm;

    private final CognitoIdentityProviderClient cognitoClient;
   @Inject
   UserProfileRepo userProfileRepo;

   @Inject
   SecurityUtils securityUtils;

    /**
     * Constructor for CognitoAuthProvider.
     */
    public CognitoAuthProvider() {
        this.cognitoClient = CognitoIdentityProviderClient.builder().build();
    }

    @Override
    public LoginResponse login(  String userId, String password) {
        return  login(null, userId, password);
    }

    @Override
    public LoginResponse login(String realm,  String userId, String password) {
        Optional<CredentialUserIdPassword> ocred;
        if (realm == null)
            ocred = credentialRepo.findByUserId(userId);
        else
            ocred = credentialRepo.findByUserId(userId, realm);

        if (!ocred.isPresent()) {
            throw new WebApplicationException(String.format("user with userId:%s could not be found in the credentials collection in realm:%s", userId, credentialRepo.getDatabaseName()));
        }

        if (Log.isDebugEnabled()) {
           Log.debugf("Login request for user: %s, realm: %s with username:%s using clientId:%s, and userpoolId:%s", userId, realm, ocred.get().getUsername(), clientId, userPoolId);
        }

        try {
            Set<String> groups = new HashSet<>();
            groups.addAll(Set.of(ocred.get().getRoles()));
            String accessToken;
            String refreshToken;

            if (isCognitoDisabled()) {
                // Validate password locally using stored hash if available
                String storedHash = ocred.get().getPasswordHash();
                if (storedHash != null && password != null && !storedHash.equals(EncryptionUtils.hashPassword(password))) {
                    throw new SecurityException("Invalid credentials");
                }
                // In disabled mode, skip AWS calls and fabricate opaque tokens
                accessToken = UUID.randomUUID().toString();
                refreshToken = UUID.randomUUID().toString();
            } else {
                AdminInitiateAuthRequest authRequest =
                    AdminInitiateAuthRequest.builder()
                        .userPoolId(userPoolId)
                        .clientId(clientId)
                        .authFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
                        .authParameters(
                            Map.of("USERNAME", ocred.get().getUsername(), "PASSWORD", password)
                        )
                        .build();

                AdminInitiateAuthResponse authResponse = cognitoClient.adminInitiateAuth(authRequest);
                AuthenticationResultType authResult = authResponse.authenticationResult();
                accessToken = authResult.accessToken();
                refreshToken = authResult.refreshToken();
                groups.addAll(getUserGroups(ocred.get().getUsername()));
            }

            SecurityIdentity identity = buildIdentity(ocred.get().getUserId(), groups);
            securityIdentityAssociation.setIdentity(identity);

            LoginPositiveResponse positive = new LoginPositiveResponse(
                    userId,
                    identity,
                    groups,
                    accessToken,
                    refreshToken,
                    new Date(
                            TokenUtils.currentTimeInSecs() + durationInSeconds
                    ).getTime(),
                    mongodbConnectionString,
                    (realm != null && !realm.isBlank()) ? realm : defaultRealm
            );
            enhanceLoginPositiveResponse(positive, (realm != null && !realm.isBlank()) ? realm : defaultRealm);
            return new LoginResponse(
                true,
                positive
            );
        } catch (NotAuthorizedException e) {
            Log.error("Authentication failed for userId: " + userId, e);
            throw new SecurityException("Invalid credentials");
        } catch (UserNotFoundException e) {
            Log.error("User not found in cognito: " + userId, e);
            throw e;
        } catch (Exception e) {
            Log.error("Unexpected error during authentication", e);
            throw new SecurityException(
                "Authentication failed: " + e.getMessage()
            );
        }
    }

    @Override
    public LoginResponse refreshTokens(String refreshToken) {
        Map<String, String> authParameters = new HashMap<>();
        authParameters.put("REFRESH_TOKEN", refreshToken);

        AdminInitiateAuthRequest refreshRequest =
            AdminInitiateAuthRequest.builder()
                .userPoolId(userPoolId)
                .clientId(clientId)
                .authFlow(AuthFlowType.REFRESH_TOKEN_AUTH)
                .authParameters(authParameters)
                .build();

        AdminInitiateAuthResponse refreshResponse =
            cognitoClient.adminInitiateAuth(refreshRequest);
        AuthenticationResultType authResult =
            refreshResponse.authenticationResult();

        // Get user info from the new access token
        GetUserRequest userRequest = GetUserRequest.builder()
            .accessToken(authResult.accessToken())
            .build();

        GetUserResponse userResponse = cognitoClient.getUser(userRequest);
        String username = userResponse.username();

        String newIdToken = authResult.idToken();
        String newRefreshToken = refreshToken;

        Set<String> groups = getUserGroups(username); // Refresh token remains the same

        SecurityIdentity identity = validateAccessToken(newIdToken);

        LoginPositiveResponse positive = new LoginPositiveResponse(
            username,
            identity,
            groups,
            newIdToken,
            newRefreshToken,
            new Date(
                TokenUtils.currentTimeInSecs() + durationInSeconds
            ).getTime(),
            mongodbConnectionString,
            defaultRealm
        );
        enhanceLoginPositiveResponse(positive, defaultRealm);
        return new LoginResponse(
            true,
            positive
        );
    }

    @Override
    public boolean usernameExists(String username) {
      return usernameExists(securityUtils.getSystemRealm(), username);
    }

   @Override
   public boolean usernameExists (String realm, String username) throws SecurityException {

         if (isCognitoDisabled()) {
            Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUsername(username, realm);
            return ocred.isPresent();
         }

      Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUsername(username, realm);
      if (!ocred.isPresent()) {
         Log.warnf("Credential not configured in database for username: %s  can not resolve credential given username in realm: %s, cognito needs username but it could not be resolved, configure credentials in realm", username, realm);
         return false;
      }
      try {
         AdminGetUserRequest request = AdminGetUserRequest.builder()
                                          .userPoolId(userPoolId)
                                          .username(username)
                                          .build();

         cognitoClient.adminGetUser(request);
         return true;
      } catch (UserNotFoundException e) {
         Log.warn(e.getMessage());
         return false;
      } catch (Exception e) {
         Log.error(String.format("Error checking user existence:%s", e.getMessage()), e);
         throw new SecurityException(String.format("Failed to check user existence:%s ", e.getMessage()),e);
      }
   }

   @Override
   public boolean userIdExists (String realm, String userId) throws SecurityException {
         if (isCognitoDisabled()) {
            Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUserId(userId, realm, true);
            return ocred.isPresent();
         }
      //return userIdExists(userId);
      // We are being given a userId and we need to now translate this to a username.  The only way we can do that is via the credential collection
      // however if the credential database does not have it / has not been set up then we either throw an exception to this effect or we lie and say its not
      // I choose to throw an exception to the caller.
      Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUserId(userId, realm, true);
      if (!ocred.isPresent()) {
         Log.warnf("userIdExists returning false, credential not configured in database for userid: %s  can not resolve username given userid in realm: %s, cognito needs username but it could not be resolved, configure credentials in realm", userId, realm);
         return false;
      }

      AdminGetUserRequest request = AdminGetUserRequest.builder()
                                       .userPoolId(userPoolId)
                                       .username(ocred.get().getUserId()) // should work with alaises are configured or not so yes userId not username
                                       .build();
      try {
         AdminGetUserResponse getUserResponse = cognitoClient.adminGetUser(request);
         Log.infof("Found userId:%s in cognito userPoolId:%s validating it matches credential from database:", ocred.get().getUserId(), userPoolId);

         if (getUserResponse.userStatus() != UserStatusType.CONFIRMED) {
            Log.warnf("User:%s has not in a confirmed state found state:%s", userId, getUserResponse.userStatus().toString());
         }
         if (!getUserResponse.username().equals(ocred.get().getUsername())) {
            Log.errorf("Cognito username:%s does not match username from database:%s", getUserResponse.username(), ocred.get().getUsername());
            throw new IllegalStateException(String.format("Cognito username does not match username from database, credentialUserName:%s, cognitoUserName:%s for userId:%s correct them to match",getUserResponse.username(), ocred.get().getUsername(), userId));
         }
         if (getUserResponse.getValueForField("sub", String.class).orElse("Not provided").equals(ocred.get().getUsername())){
            Log.warnf("sub field in cognito subject:%s does not match credential record username:%s", getUserResponse.getValueForField("sub", String.class).orElse("Not Provided"), ocred.get().getUsername());
            throw new IllegalStateException(String.format("sub field in cognito subject does not match credential record username, credentialUserName:%s, cognito subject:%s for userId:%s correct them to match",getUserResponse.getValueForField("sub", String.class).orElse("Not Provided"), ocred.get().getUsername(), userId));
         }

         return true;
      } catch (UserNotFoundException e) {
         Log.warnf("userId:%s not found in cognito userPoolId:%s, userNotFoundExceptionMsg:%s",userId, userPoolId, e.getMessage());
         return false;
      }

   }


    @Override
    public boolean userIdExists(String userId) {
         return userIdExists(securityUtils.getSystemRealm(), userId);
    }


   @Override
   public void changePassword(String userId, String oldPassword, String newPassword, Boolean forceChangePassword) {
       changePassword(securityUtils.getSystemRealm(), userId, oldPassword, newPassword, forceChangePassword);
   }

   @Override
   public void changePassword(String realm, String userId, String oldPassword, String newPassword, Boolean forceChangePassword) {
       Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUserId(userId, realm);
       if (!ocred.isPresent()) {
          Log.warnf("Credential not configured in database for userid: %s  can not resolve username given userid in realm: %s, cognito needs username but it could not be resolved, configure credentials in realm", userId, realm);
          return;
       }

      AdminSetUserPasswordRequest request = AdminSetUserPasswordRequest.builder()
                                               .userPoolId(userPoolId)     // Your user pool ID
                                               .username(userId)         // The username
                                               .password(newPassword)          // New password
                                               .permanent(forceChangePassword != null && forceChangePassword)                      // Set to true to avoid requiring password change on next login
                                               .build();



      try {
         cognitoClient.adminSetUserPassword(request);
         Log.infof("Admin reset password for userId:%s in realm: %s  successfully", userId, realm);
      } catch (CognitoIdentityProviderException e) {
         Log.warnf("Admin password for userId:%s in realm: %s reset failed:%s " , userId, realm, e.awsErrorDetails().errorMessage());
         throw new SecurityException(String.format("Failed to reset admin password for userId:%s in realm: %s:%s ", userId, realm, e.awsErrorDetails().errorMessage()), e);
      }

      ocred.get().setPasswordHash(EncryptionUtils.hashPassword(newPassword));
      ocred.get().setForceChangePassword(forceChangePassword);

      credentialRepo.save(ocred.get());
   }


   @Override
   public void createUser (String realm, String userId, String password, String username, Set<String> roles, DomainContext domainContext) throws SecurityException {
       createUser(realm, userId, password, null, username, roles, domainContext);
   }

   @Override
   public void createUser (String realm, String userId, String password, Boolean forceChangePassword,
                        String username, Set<String> roles, DomainContext domainContext) {
     requireValidEmail(userId);
     roles = (roles != null) ? roles : Collections.emptySet();

     // 1) Try to retrieve existing Cognito user by email
     Optional<UserType> oByEmail = retrieveUserId(userId);
     if (oByEmail.isPresent()) {
         String cognitoUsername = oByEmail.get().username();
         String cognitoSub = fetchSubViaAdminGetUser(cognitoUsername);

         // 2) Reconcile or create credential
         Optional<CredentialUserIdPassword> oCred = credentialRepo.findByUserId(userId, realm, true);
         if (oCred.isPresent()) {
             CredentialUserIdPassword cred = oCred.get();
             // Ensure the local record references Cognito’s values
             if (!Objects.equals(cred.getUsername(), cognitoUsername) || !Objects.equals(cred.getSubject(), cognitoSub)) {
                 //throw new SecurityException("Credential mismatch with Cognito");
                 // Or: heal by updating credential to match Cognito
                  cred.setUsername(cognitoUsername);
                  cred.setSubject(cognitoSub);
                  credentialRepo.save(realm, cred);
                 // ... then save
             }
             // Optionally update roles/password/domainContext
         } else {
             CredentialUserIdPassword cred = new CredentialUserIdPassword();
             cred.setRefName(cognitoUsername);
             cred.setUserId(userId);
             cred.setUsername(cognitoUsername);     // <- store Cognito username
             cred.setSubject(cognitoSub);           // <- store Cognito sub
             if (password != null) cred.setPasswordHash(EncryptionUtils.hashPassword(password));
             cred.setDomainContext(domainContext);
             cred.setRoles(roles.toArray(new String[0]));
             cred.setLastUpdate(new Date());
             credentialRepo.save(realm, cred);
         }

         if (!roles.isEmpty()) assignRoles(cognitoUsername, roles);
         return;
     }

     // 3) Cognito user does not exist: create it
     String requestedUsername = (username != null && !username.isBlank()) ? username : userId;
     AdminCreateUserResponse createResp = cognitoClient.adminCreateUser(
         AdminCreateUserRequest.builder()
             .userPoolId(userPoolId)
             .username(requestedUsername)
             .temporaryPassword(password)
             .messageAction((forceChangePassword == null || !forceChangePassword)
                            ? MessageActionType.SUPPRESS : MessageActionType.RESEND)
             .userAttributes(AttributeType.builder().name("email").value(userId).build(),
                             AttributeType.builder().name("email_verified").value("true").build())
             .build()
     );

     String resolvedUsername = (createResp.user() != null && createResp.user().username() != null)
         ? createResp.user().username() : requestedUsername;
     String sub = fetchSubViaAdminGetUser(resolvedUsername);

     if (forceChangePassword != null && !forceChangePassword) {
         cognitoClient.adminSetUserPassword(AdminSetUserPasswordRequest.builder()
             .userPoolId(userPoolId)
             .username(resolvedUsername)
             .password(password)
             .permanent(true)
             .build());
     }

     // 4) Create or verify credential referencing Cognito-assigned identifiers
     Optional<CredentialUserIdPassword> oCred = credentialRepo.findByUserId(userId, realm, true);
     if (oCred.isPresent()) {
         CredentialUserIdPassword cred = oCred.get();
         if (!Objects.equals(cred.getUsername(), resolvedUsername) || !Objects.equals(cred.getSubject(), sub)) {
             cred.setUsername(resolvedUsername);
             cred.setSubject(sub);
             credentialRepo.save(realm, cred);
         }
     } else {
         CredentialUserIdPassword cred = new CredentialUserIdPassword();
         cred.setRefName(resolvedUsername);
         cred.setUserId(userId);
         cred.setUsername(resolvedUsername);  // <- Cognito username
         cred.setSubject(sub);                // <- Cognito sub
         if (password != null) cred.setPasswordHash(EncryptionUtils.hashPassword(password));
         cred.setDomainContext(domainContext);
         cred.setRoles(roles.toArray(new String[0]));
         cred.setLastUpdate(new Date());
         credentialRepo.save(realm, cred);
     }

     if (!roles.isEmpty()) assignRoles(resolvedUsername, roles);
   }

    @Override
    public boolean removeUserWithUsername (String realm, String username) throws ReferentialIntegrityViolationException {
        return removeUserWithUsername(username);
    }
   @Override
   public boolean removeUserWithUsername(String username)
      throws ReferentialIntegrityViolationException {
      if (isCognitoDisabled()) {
         Log.debug("Cognito disabled: skipping remote user removal by username");
         return true;
      }
      // delete the user in Cognito
      try {
         AdminDeleteUserRequest deleteRequest =
            AdminDeleteUserRequest.builder()
               .userPoolId(userPoolId)
               .username(username)
               .build();

         AdminDeleteUserResponse response =  cognitoClient.adminDeleteUser(deleteRequest);
         if (!response.sdkHttpResponse().isSuccessful()) {
            Log.warnf("remove username %s  failed with message: %s", username, response.sdkHttpResponse().statusText().orElse(""));
            return false;
         } else {
            Log.infof("remove username %s  successful", username);
            return true;
         }
      } catch (UserNotFoundException e) {
         Log.warnf("Username %s could not be found", username);
         return false;
      }
   }

    @Override
    public boolean removeUserWithUserId (String userId) throws ReferentialIntegrityViolationException {
        return removeUserWithUserId(securityUtils.getSystemRealm(),userId);
    }

   @Override
   public boolean removeUserWithUserId (String realm, String userId) throws ReferentialIntegrityViolationException {
         if (isCognitoDisabled()) {
            Log.debug("Cognito disabled: skipping remote user removal by userId");
            return true;
         }
      Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUserId(userId, realm);
      String username;
      if (!ocred.isPresent()) {
         Log.warnf("Credential not configured in database for userid: %s  can not resolve username given userid in realm: %s, cognito needs username but it could not be resolved, configure credentials in realm", userId, credentialRepo.getDatabaseName());
         return false;
      } else {
         username = ocred.get().getUsername();
      }


      try {
         AdminDeleteUserRequest deleteRequest =
            AdminDeleteUserRequest.builder()
               .userPoolId(userPoolId)
               .username(username)
               .build();

         AdminDeleteUserResponse response = cognitoClient.adminDeleteUser(deleteRequest);
         if (!response.sdkHttpResponse().isSuccessful()) {
            Log.warnf("remove username %s  failed with message: %s", username, response.sdkHttpResponse().statusText().orElse(""));
            return false;
         } else {
            Log.infof("remove username %s  successful", username);
            return true;
         }
      }
      catch (UserNotFoundException e) {
         Log.warnf("Username %s could not be found", username);
         return false;
      }
      catch (Exception e) {
         Log.errorf(
            "Error checking user existence for username %s",
            ocred.get().getUsername(),
            e
         );
         throw new SecurityException(
            "Failed to check user existence: " + e.getMessage()
         );
      }
   }

   @Override
    public void assignRoles (String realm, String username, Set<String> roles) throws SecurityException {
         assignRoles(username, roles);
    }

    @Override
    public void removeRoles (String realm, String username, Set<String> roles) throws SecurityException {
        removeRoles(username, roles);
    }

    @Override
    public Set<String> getUserRoles (String realm, String username) throws SecurityException {
       return getUserRoles(username);
    }



    private SecurityIdentity buildIdentity(String userId, Set<String> roles) {
        if (Log.isDebugEnabled()) {
            Log.debug("Building identity for userId: " + userId + " with roles: " + roles);
        }
        QuarkusSecurityIdentity.Builder builder =
            QuarkusSecurityIdentity.builder();
        builder.setPrincipal(
            new Principal() {
                @Override
                public String getName() {
                    return userId;
                }
            }
        );
        roles.forEach(builder::addRole);

        // Add any additional attributes needed for your application
        builder.addAttribute("token_type", "custom");
        builder.addAttribute("auth_time", System.currentTimeMillis());

        return builder.build();
    }

    @Override
    public SecurityIdentity validateAccessToken(String token) {
        try {
            // Validate the token using CognitoTokenValidator
            JsonWebToken webToken = jwtParser.parse(token);
            String username = webToken.claim("username").toString();
            Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUsername(username);
            if (!ocred.isPresent()) {
                throw new IllegalStateException("Credential not configured in database for username: " + username + " can not resolve userid given username in realm:" + credentialRepo.getDatabaseName() + ", cognito needs userid but it could not be resolved, configure credentials in realm");
            }
            Set<String> roles = new HashSet<>();
            if (webToken.containsClaim("cognito:groups")) {
                Optional<JsonArray> ogroupsArray = webToken.claim(
                    "cognito:groups"
                );
                if (
                    ogroupsArray.isPresent()
                ) for (JsonValue value : ogroupsArray.get()) {
                    roles.add(value.toString().replace("\"", "")); // Remove quotes from the string
                }
            } else {
                roles = getUserGroups(username);
            }

            SecurityIdentity identity = buildIdentity(ocred.get().getUserId(), roles);
            // Set the SecurityIdentity for the current request
            securityIdentityAssociation.setIdentity(identity);
            return identity;
        } catch (Exception e) {
            Log.error("Token validation failed", e);
            throw new SecurityException("Invalid token");
        }
    }

    @Override
    public String getName() {
        return "cognito";
    }

    private Set<String> getUserGroups(String username) {
        try {
            AdminListGroupsForUserRequest groupsRequest =
                AdminListGroupsForUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .build();

            AdminListGroupsForUserResponse groupsResponse =
                cognitoClient.adminListGroupsForUser(groupsRequest);

            return groupsResponse
                .groups()
                .stream()
                .map(GroupType::groupName)
                .collect(Collectors.toSet());
        } catch (Exception e) {
            Log.error(String.format("Failed to get user groups for username:%s", username), e);
            return new HashSet<>();
        }
    }

    public Optional<UserType> retrieveUserId(String userId) {
        try {
            ListUsersRequest request = ListUsersRequest.builder()
                                          .userPoolId(userPoolId)
                                          .filter("email = \"" + userId + "\"")
                                          .limit(1) // Limit to 1 since email should be unique
                                          .build();

            ListUsersResponse response = cognitoClient.listUsers(request);

            if (!response.users().isEmpty()) {
                return Optional.of(response.users().get(0));
            } else {
                return Optional.empty();
            }
        } catch (Exception e) {
            Log.error("Failed to retrieve user by email", e);
            throw new SecurityException("Failed to retrieve user by email: " + e.getMessage());
        }
    }

    // Helper: validate email format consistently
    private void requireValidEmail(String userId) {
        if (!ValidateUtils.isValidEmailAddress(userId)) {
            throw new IllegalArgumentException("UserId should be a valid email address, given: " + userId);
        }
    }

    // Helper: fetch the Cognito 'sub' attribute via AdminGetUser
    private String fetchSubViaAdminGetUser(String username) {
        try {
            AdminGetUserResponse resp = cognitoClient.adminGetUser(
                AdminGetUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .build()
            );
            String sub = resp.userAttributes().stream()
                .filter(a -> "sub".equals(a.name()))
                .map(AttributeType::value)
                .findFirst()
                .orElse(null);
            if (sub == null || sub.isBlank()) {
                throw new SecurityException("Cognito user missing 'sub' attribute for username:" + username);
            }
            return sub;
        } catch (UserNotFoundException e) {
            throw new SecurityException(String.format("User with username:%s not found in Cognito", username));
        } catch (Exception e) {
            Log.error("Failed to fetch 'sub' via AdminGetUser", e);
            throw new SecurityException("Failed to fetch 'sub' via AdminGetUser: " + e.getMessage(), e);
        }
    }

    public void retrieveUserByUsername(String username) {
        // using the cognito api's retrieve the user using the userId
        try {
            AdminGetUserRequest request = AdminGetUserRequest.builder()
                                             .userPoolId(userPoolId)
                                             .username(username)
                                             .build();

            AdminGetUserResponse response = cognitoClient.adminGetUser(request);
            if (!response.sdkHttpResponse().isSuccessful()) {
                throw new SecurityException(
                    "Failed to retrieve user: " + response.toString()
                );
            }
            Log.info("== UserAttributes" );
            response.userAttributes().stream().forEach(attr -> {Log.infof("    %s:%s", attr.name(), attr.value());});
        } catch (UserNotFoundException e) {
            throw new SecurityException(String.format("User  with username: %s not found: " , username));
        } catch (Exception e) {
            Log.error("Failed to retrieve user", e);
            throw new SecurityException(
                "Failed to retrieve user: " + e.getMessage()
            );
        }
    }

    @Override
    public void createUser(
        String userId,
        String password,
        String username,
        Set<String> roles,
        DomainContext domainContext
    ) throws SecurityException {

        createUser( securityUtils.getSystemRealm(),  userId, password, username, roles, domainContext);
    }

   @Override
   public void createUser (String userId, String password, Boolean forceChangePassword, String username, Set<String> roles, DomainContext domainContext) throws SecurityException {
      createUser( securityUtils.getSystemRealm(),  userId, password, forceChangePassword, username, roles, domainContext);
   }


   @Override
    public void assignRoles(String username, Set<String> roles)
        throws SecurityException {
        if (isCognitoDisabled()) {
            Log.debug("Cognito disabled: skipping remote role assignment");
            return;
        }
        try {
            for (String role : roles) {
                // First ensure the group exists
                try {
                    CreateGroupRequest createGroupRequest =
                        CreateGroupRequest.builder()
                            .groupName(role)
                            .userPoolId(userPoolId)
                            .build();
                    cognitoClient.createGroup(createGroupRequest);
                } catch (GroupExistsException e) {
                    // Group already exists, continue
                }

                // Add user to group
                AdminAddUserToGroupRequest groupRequest =
                    AdminAddUserToGroupRequest.builder()
                        .userPoolId(userPoolId)
                        .username(username)
                        .groupName(role)
                        .build();

                cognitoClient.adminAddUserToGroup(groupRequest);
            }
        } catch (Exception e) {
            Log.error("Failed to assign roles", e);
            throw new SecurityException(
                "Failed to assign roles: " + e.getMessage()
            );
        }
    }

    @Override
    public void removeRoles(String username, Set<String> roles)
        throws SecurityException {
        if (isCognitoDisabled()) {
            Log.debug("Cognito disabled: skipping remote role removal");
            return;
        }
        try {
            for (String role : roles) {
                AdminRemoveUserFromGroupRequest request =
                    AdminRemoveUserFromGroupRequest.builder()
                        .userPoolId(userPoolId)
                        .username(username)
                        .groupName(role)
                        .build();

                cognitoClient.adminRemoveUserFromGroup(request);
            }
        } catch (Exception e) {
            Log.error("Failed to remove roles", e);
            throw new SecurityException(
                "Failed to remove roles: " + e.getMessage()
            );
        }
    }

    @Override
    public Set<String> getUserRoles(String username) throws SecurityException {
        if (isCognitoDisabled()) {
            try {
                Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUsername(username);
                if (ocred.isPresent() && ocred.get().getRoles() != null) {
                    return Arrays.stream(ocred.get().getRoles()).collect(Collectors.toSet());
                }
                return new HashSet<>();
            } catch (Exception e) {
                Log.error("Failed to get user roles from credential repo", e);
                return new HashSet<>();
            }
        }
        return getUserGroups(username);
    }


}
