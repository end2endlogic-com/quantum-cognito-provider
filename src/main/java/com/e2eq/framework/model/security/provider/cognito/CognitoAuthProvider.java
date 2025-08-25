package com.e2eq.framework.model.security.provider.cognito;

import com.e2eq.framework.exceptions.ReferentialIntegrityViolationException;
import com.e2eq.framework.model.persistent.base.DataDomain;
import com.e2eq.framework.model.persistent.morphia.CredentialRepo;

import com.e2eq.framework.model.persistent.morphia.UserProfileRepo;
import com.e2eq.framework.model.persistent.security.CredentialRefreshToken;
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

import io.smallrye.jwt.auth.principal.JWTParser;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.JsonArray;
import jakarta.json.JsonValue;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.stream.Collectors;


import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
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

      @ConfigProperty(name = "auth.jwt.secret")
      String secretKey;

      @ConfigProperty(name = "auth.jwt.expiration")
      Long expirationInMinutes;

      @ConfigProperty(name = "mp.jwt.verify.issuer")
      String issuer;

      @ConfigProperty(name = "com.b2bi.jwt.duration" , defaultValue = "3600")
      Long durationInSeconds;


    private boolean isCognitoDisabled() {
        try {
            String up = (userPoolId == null) ? "" : userPoolId.trim();
            String cid = (clientId == null) ? "" : clientId.trim();
            return up.equalsIgnoreCase("ignore") || cid.equalsIgnoreCase("ignore");
        } catch (Exception e) {
            return true;
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

    private String generateRefreshToken (String userId, String accessToken, long durationInSeconds) throws IOException,
                                                                                                              NoSuchAlgorithmException,
                                                                                                              InvalidKeySpecException {

          String refreshToken = TokenUtils.generateRefreshToken(
             userId,
             TokenUtils.currentTimeInSecs() + durationInSeconds + TokenUtils.REFRESH_ADDITIONAL_DURATION_SECONDS,
             issuer);

          CredentialRefreshToken refreshToken1 = CredentialRefreshToken.builder()
                                                    .userId(userId)
                                                    .refreshToken(refreshToken)
                                                    .accessToken(accessToken)
                                                    .creationDate(new Date())
                                                    .lastRefreshDate(new Date())
                                                    .expirationDate(new Date(System.currentTimeMillis() + (durationInSeconds * 1000) + TokenUtils.REFRESH_ADDITIONAL_DURATION_SECONDS))
                                                    .build();

          return refreshToken;
       }






    @Override
    public LoginResponse login(String realm,  String userId, String password) {
        Optional<CredentialUserIdPassword> ocred;
        if (realm == null)
            ocred = credentialRepo.findByUserId(userId,securityUtils.getSystemRealm(), true);
        else
            ocred = credentialRepo.findByUserId(userId, realm, true);

        if (!ocred.isPresent()) {
            throw new WebApplicationException(String.format("user with userId:%s could not be found in the credentials collection in realm:%s", userId, credentialRepo.getDatabaseName()));
        }

        if (Log.isDebugEnabled()) {
           Log.debugf("Login request for user: %s, realm: %s with subject:%s using clientId:%s, and userpoolId:%s", userId, realm, ocred.get().getSubject(), clientId, userPoolId);
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
                accessToken =
                   TokenUtils.generateUserToken(
                                        ocred.get().getSubject(),
                                        groups,
                                        TokenUtils.expiresAt(durationInSeconds),
                                        issuer);


                refreshToken =  generateRefreshToken(ocred.get().getUserId(), accessToken,
                                                     TokenUtils.currentTimeInSecs() + durationInSeconds + TokenUtils.REFRESH_ADDITIONAL_DURATION_SECONDS);

            } else {
                AdminInitiateAuthRequest authRequest =
                    AdminInitiateAuthRequest.builder()
                        .userPoolId(userPoolId)
                        .clientId(clientId)
                        .authFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
                        .authParameters(
                            Map.of("USERNAME", ocred.get().getUserId(), "PASSWORD", password)
                        )
                        .build();

                AdminInitiateAuthResponse authResponse = cognitoClient.adminInitiateAuth(authRequest);
                AuthenticationResultType authResult = authResponse.authenticationResult();
                accessToken = authResult.accessToken();
                refreshToken = authResult.refreshToken();
                groups.addAll(getUserGroupsForSubject(ocred.get().getSubject()));
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

        Set<String> groups = getUserGroupsForUserId(username); // Refresh token remains the same

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
        return new LoginResponse(
            true,
            positive
        );
    }

    @Override
    public boolean subjectExists(String subject) {
      return subjectExists(securityUtils.getSystemRealm(), subject);
    }

   @Override
   public boolean subjectExists (String realm, String subject) throws SecurityException {

         if (isCognitoDisabled()) {
            Optional<CredentialUserIdPassword> ocred = credentialRepo.findBySubject(subject, realm, true);
            return ocred.isPresent();
         }

      Optional<CredentialUserIdPassword> ocred = credentialRepo.findBySubject(subject, realm, true);
      if (!ocred.isPresent()) {
         Log.warnf("Credential not configured in database for subject: %s  can not resolve credential given username in realm: %s, cognito needs username but it could not be resolved, configure credentials in realm", subject, realm);
         return false;
      }
      try {
         AdminGetUserRequest request = AdminGetUserRequest.builder()
                                          .userPoolId(userPoolId)
                                          .username(subject)
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
         Log.warnf("userIdExists: returning false, credential not configured in database for userid: %s  can not resolve username given userid in realm: %s, cognito needs username but it could not be resolved, configure credentials in realm", userId, realm);
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
         if (!getUserResponse.username().equals(ocred.get().getSubject() )) {
            Log.errorf("Cognito username:%s does not match subject from database:%s", getUserResponse.username(), ocred.get().getSubject());
            throw new IllegalStateException(String.format("Cognito username does not match subject from database, CognitoUserName:%s, credentialSubject:%s for credential userId:%s correct them to match",getUserResponse.username(), ocred.get().getSubject(), userId));
         }
         if (getUserResponse.getValueForField("sub", String.class).orElse("Not provided").equals(ocred.get().getSubject())){
            Log.warnf("sub field in cognito subject:%s does not match credential record username:%s", getUserResponse.getValueForField("sub", String.class).orElse("Not Provided"), ocred.get().getSubject());
            throw new IllegalStateException(String.format("sub field in cognito subject does not match credential record subject, credentialSubject:%s, cognito subject:%s for userId:%s correct them to match",getUserResponse.getValueForField("sub", String.class).orElse("Not Provided"), ocred.get().getSubject(), userId));
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
       Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUserId(userId, realm, true);
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
   public String createUser (String realm, String userId, String password,  Set<String> roles, DomainContext domainContext) throws SecurityException {
      return createUser(realm, userId, password, null,  roles, domainContext);
   }

   @Override
   public String createUser (String realm, String userId, String password, Boolean forceChangePassword,  Set<String> roles, DomainContext domainContext) throws SecurityException {
       return createUser(realm, userId, password, forceChangePassword, roles, domainContext, null);
   }

   @Override
   public String createUser (String userId, String password, String username, Set<String> roles, DomainContext domainContext, DataDomain dataDomain) throws SecurityException {
           return createUser(securityUtils.getSystemRealm(), userId, password, null,  roles, domainContext, dataDomain);
   }

   @Override
   public String createUser (String userId, String password, Boolean forceChangePassword,  Set<String> roles, DomainContext domainContext, DataDomain dataDomain) throws SecurityException {
        return createUser(securityUtils.getSystemRealm(), userId, password, forceChangePassword, roles, domainContext, dataDomain);
   }

   @Override
   public String createUser (String realm, String userId, String password, Boolean forceChangePassword,
                         Set<String> roles, DomainContext domainContext, DataDomain dataDomain) {
     requireValidEmail(userId);
     roles = (roles != null) ? roles : Collections.emptySet();
     String subject;

     // 1) Try to retrieve existing Cognito user by email/userid
     Optional<UserType> oByEmail = retrieveUserId(userId);
     if (oByEmail.isPresent()) {
        String cognitoUsername = oByEmail.get().username();
        Optional<String> ocognitoSub = getSubjectForUserId(securityUtils.getSystemRealm(), cognitoUsername);
        if (!ocognitoSub.isPresent()) {
           Log.warnf("Could not find Cognito subject for userId:%s in realm: %s, cognito username:%s so creating user", userId, realm, cognitoUsername);
           String requestedUsername = userId;
           AdminCreateUserResponse createResp = cognitoClient.adminCreateUser(
              AdminCreateUserRequest.builder()
                 .userPoolId(userPoolId)
                 .username(requestedUsername)
                 .temporaryPassword(password)
                 .messageAction((forceChangePassword == null || !forceChangePassword)
                                   ? MessageActionType.SUPPRESS : MessageActionType.RESEND)
                 .userAttributes(AttributeType.builder().name("email").value(userId).build(),
                    AttributeType.builder().name("email_verified").value("true").build())
                 .build());


// Make the password permanent so the user doesn't have to change it
           cognitoClient.adminSetUserPassword(AdminSetUserPasswordRequest.builder()
                                                 .userPoolId(userPoolId)
                                                 .username(createResp.user().username())
                                                 .password(password)       // same password, but now permanent
                                                 .permanent(true)
                                                 .build());
           // extract the subject from the attributes
           ocognitoSub = createResp.user().attributes().stream()
                            .filter(attr -> attr.name().equals("sub"))
                            .map(AttributeType::value)
                            .findFirst();

           if (!ocognitoSub.isPresent()) {
              throw new SecurityException("Could not find Cognito subject for userId:" + userId + " in realm: " + realm + " and cognito username: " + cognitoUsername);
           } else {
              subject = ocognitoSub.get();
           }
        } else {
           subject = ocognitoSub.get();
        }
     } else {
        // 1.1) If no existing Cognito user, create a new user
        AdminCreateUserResponse createResp = cognitoClient.adminCreateUser(
           AdminCreateUserRequest.builder()
              .userPoolId(userPoolId)
              .username(userId)
              .temporaryPassword(password)
              .messageAction((forceChangePassword == null ||!forceChangePassword)
                                ? MessageActionType.SUPPRESS : MessageActionType.RESEND)
              .userAttributes(AttributeType.builder().name("email").value(userId).build(),
                    AttributeType.builder().name("email_verified").value("true").build())
              .build());

        cognitoClient.adminSetUserPassword(AdminSetUserPasswordRequest.builder()
                                              .userPoolId(userPoolId)
                                              .username(createResp.user().username())
                                              .password(password)       // same password, but now permanent
                                              .permanent(true)
                                              .build());

        Optional<String> osub = createResp.user().attributes().stream()
                         .filter(attr -> attr.name().equals("sub"))
                         .map(AttributeType::value)
                         .findFirst();
        if (!osub.isPresent()) {
           throw new SecurityException("Could not find Cognito subject for userId:" + userId + " in realm: " + realm);
        } else {
           subject = osub.get();
        }
     }


         // 2) Reconcile or create credential
         Optional<CredentialUserIdPassword> oCred = credentialRepo.findByUserId(userId, realm, true);
         if (oCred.isPresent()) {
             CredentialUserIdPassword cred = oCred.get();
             // Ensure the local record references Cognito’s values
             if (!Objects.equals(cred.getUserId(), userId) || !Objects.equals(cred.getSubject(), subject)) {
                 //throw new SecurityException("Credential mismatch with Cognito");
                 // Or: heal by updating credential to match Cognito
                  cred.setUserId(userId);
                  cred.setSubject(subject);
                  credentialRepo.save(realm, cred);
                 // ... then save
             }
             // Optionally update roles/password/domainContext
         } else {
             CredentialUserIdPassword cred = new CredentialUserIdPassword();
             cred.setRefName(subject);
             cred.setUserId(userId);
             cred.setSubject(subject);           // <- store Cognito sub
             if (password != null) cred.setPasswordHash(EncryptionUtils.hashPassword(password));
             cred.setDomainContext(domainContext);
             cred.setRoles(roles.toArray(new String[0]));
             cred.setLastUpdate(new Date());
             cred.setDataDomain(dataDomain);
             credentialRepo.save(realm, cred);
         }

         if (!roles.isEmpty())
            assignRolesForUserId(userId, roles);

        return subject;
     }

    @Override
    public boolean removeUserWithSubject (String realm, String subject) throws ReferentialIntegrityViolationException {
        return removeUserWithSubject(subject);
    }
   @Override
   public boolean removeUserWithSubject(String subject)
      throws ReferentialIntegrityViolationException {
      if (isCognitoDisabled()) {
         Log.debug("Cognito disabled: skipping remote user removal by username");
         return true;
      }

      Optional<CredentialUserIdPassword> ocred = credentialRepo.findBySubject(subject, securityUtils.getSystemRealm(), true);
      if (!ocred.isPresent()) {
         Log.debugf("No credential found for subject %s", subject);
         return false;
      }


      // delete the user in Cognito
      try {
         AdminDeleteUserRequest deleteRequest =
            AdminDeleteUserRequest.builder()
               .userPoolId(userPoolId)
               .username(ocred.get().getUserId())
               .build();

         AdminDeleteUserResponse response =  cognitoClient.adminDeleteUser(deleteRequest);
         if (!response.sdkHttpResponse().isSuccessful()) {
            Log.warnf("remove username %s  failed with message: %s", ocred.get().getUserId(), response.sdkHttpResponse().statusText().orElse(""));
            return false;
         } else {
            Log.infof("remove username %s  successful", ocred.get().getUserId());
            return true;
         }
      } catch (UserNotFoundException e) {
         Log.warnf("Username %s could not be found", ocred.get().getUserId());
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
      Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUserId(userId, realm, true);
      String username;
      if (!ocred.isPresent()) {
         Log.warnf("Credential not configured in database for userid: %s  can not resolve username given userid in realm: %s, cognito needs username but it could not be resolved, configure credentials in realm", userId, credentialRepo.getDatabaseName());
         return false;
      } else {
         username = ocred.get().getUserId();
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
            ocred.get().getUserId(),
            e
         );
         throw new SecurityException(
            "Failed to check user existence: " + e.getMessage()
         );
      }
   }

   @Override
    public void assignRolesForUserId (String realm, String userId, Set<String> roles) throws SecurityException {
         assignRolesForUserId(userId, roles);
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
            String subject = webToken.claim("sub").toString();
            Optional<CredentialUserIdPassword> ocred = credentialRepo.findBySubject(subject);
            if (!ocred.isPresent()) {
                throw new IllegalStateException("Credential not configured in database for subject: " + subject + " can not resolve userid given username in realm:" + credentialRepo.getDatabaseName() + ", cognito needs userid but it could not be resolved, configure credentials in realm");
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
                roles = getUserGroupsForSubject(subject);
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
    private String fetchSubViaAdminGetUser(String userId) {
        try {
            AdminGetUserResponse resp = cognitoClient.adminGetUser(
                AdminGetUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(userId)
                    .build()
            );
            String sub = resp.userAttributes().stream()
                .filter(a -> "sub".equals(a.name()))
                .map(AttributeType::value)
                .findFirst()
                .orElse(null);
            if (sub == null || sub.isBlank()) {
                throw new SecurityException("Cognito user missing 'sub' attribute for userId:" + userId);
            }
            return sub;
        } catch (UserNotFoundException e) {
            throw new SecurityException(String.format("User with userId:%s not found in Cognito", userId));
        } catch (Exception e) {
            Log.error("Failed to fetch 'sub' via AdminGetUser", e);
            throw new SecurityException("Failed to fetch 'sub' via AdminGetUser: " + e.getMessage(), e);
        }
    }

    public void retrieveUserByUserId(String userId) {
        // using the cognito api's retrieve the user using the userId
        try {
            AdminGetUserRequest request = AdminGetUserRequest.builder()
                                             .userPoolId(userPoolId)
                                             .username(userId)
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
            throw new SecurityException(String.format("User  with userId: %s not found: " , userId));
        } catch (Exception e) {
            Log.error("Failed to retrieve user", e);
            throw new SecurityException(
                "Failed to retrieve user: " + e.getMessage()
            );
        }
    }

    @Override
    public String createUser(
        String userId,
        String password,
        Set<String> roles,
        DomainContext domainContext
    ) throws SecurityException {

        return createUser( securityUtils.getSystemRealm(),  userId, password,  roles, domainContext);
    }

   @Override
   public String createUser (String userId, String password, Boolean forceChangePassword, Set<String> roles, DomainContext domainContext) throws SecurityException {
      return createUser( securityUtils.getSystemRealm(),  userId, password, forceChangePassword,  roles, domainContext);
   }

   @Override
   public String createUser (String userId, String password, Set<String> roles, DomainContext domainContext, DataDomain dataDomain) throws SecurityException {
      return createUser(securityUtils.getSystemRealm(),  userId, password, roles, domainContext, dataDomain);
   }


   @Override
    public void assignRolesForUserId(String userId, Set<String> roles)
        throws SecurityException {
        if (isCognitoDisabled()) {
            Log.debug("Cognito disabled: skipping remote role assignment");
            return;
        }
        try {

           // validate that userId exists in Cognito
           if (!userIdExists(userId)) {
              throw new SecurityException("User does not exist in Cognito: " + userId);
           }
            // Normalize target roles (null-safe)
            Set<String> targetRoles = (roles == null) ? Collections.emptySet() : new HashSet<>(roles);

            // Fetch only Cognito groups for reconciliation (exclude local credential roles)
            Set<String> currentCognitoGroups = getCognitoGroupsForUserIdOnly(userId);

            // Compute deltas
            Set<String> toAdd = new HashSet<>(targetRoles);
            toAdd.removeAll(currentCognitoGroups);

            Set<String> toRemove = new HashSet<>(currentCognitoGroups);
            toRemove.removeAll(targetRoles);

            if (toAdd.isEmpty() && toRemove.isEmpty()) {
                Log.debugf("No role changes required for user %s. Current roles already match target.", userId);
                return;
            }

            // Ensure groups exist before adding the user to them
            for (String role : toAdd) {
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
            }

            // Remove roles that should no longer be present
            for (String role : toRemove) {
                AdminRemoveUserFromGroupRequest request =
                    AdminRemoveUserFromGroupRequest.builder()
                        .userPoolId(userPoolId)
                        .username(userId)
                        .groupName(role)
                        .build();

                cognitoClient.adminRemoveUserFromGroup(request);
            }

            // Add missing roles
            for (String role : toAdd) {
                AdminAddUserToGroupRequest groupRequest =
                    AdminAddUserToGroupRequest.builder()
                        .userPoolId(userPoolId)
                        .username(userId)
                        .groupName(role)
                        .build();

                cognitoClient.adminAddUserToGroup(groupRequest);
            }

            Log.infof("Updated roles for user %s. Added: %s, Removed: %s", userId, toAdd, toRemove);
        } catch (Exception e) {
            Log.error("Failed to assign roles", e);
            throw new SecurityException(
                "Failed to assign roles: " + e.getMessage()
            );
        }
    }

   @Override
   public void assignRolesForSubject (String subject, Set<String> roles) throws SecurityException {
         credentialRepo.findBySubject(securityUtils.getSystemRealm(), subject);
   }

   @Override
   public void assignRolesForSubject (String realm, String subject, Set<String> roles) throws SecurityException {

   }

    @Override
    public void removeRolesForUserId(String userId, Set<String> roles)
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
                        .username(userId)
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
    public Set<String> getUserRolesForUserId(String userId) throws SecurityException {
        return getUserRolesForUserId(securityUtils.getSystemRealm(), userId);
    }

   @Override
   public Set<String> getUserRolesForUserId (String realm, String userId) throws SecurityException {
      if (isCognitoDisabled()) {
         try {
            Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUserId(userId, securityUtils.getSystemRealm(), true);
            if (ocred.isPresent() && ocred.get().getRoles() != null) {
               return Arrays.stream(ocred.get().getRoles()).collect(Collectors.toSet());
            }
            return new HashSet<>();
         } catch (Exception e) {
            Log.error("Failed to get user roles from credential repo", e);
            return new HashSet<>();
         }
      }
      return getUserGroupsForUserId(userId);
   }


   @Override
   public Set<String> getUserRolesForSubject (String subject) throws SecurityException {
      return getUserRolesForSubject(securityUtils.getSystemRealm(), subject);
   }

   @Override
   public Set<String> getUserRolesForSubject (String realm, String subject) throws SecurityException {
      return getUserGroupsForSubject(realm, subject);
   }



   private Set<String> getUserGroupsForUserId(String userId) {
      return getUserGroupsForUserId(securityUtils.getSystemRealm(), userId);
   }

   private Set<String> getUserGroupsForUserId(String realm, String userId) {
      try {
         AdminListGroupsForUserRequest groupsRequest =
            AdminListGroupsForUserRequest.builder()
               .userPoolId(userPoolId)
               .username(userId)
               .build();

         AdminListGroupsForUserResponse groupsResponse =
            cognitoClient.adminListGroupsForUser(groupsRequest);

         Set<String> roles = groupsResponse
                                .groups()
                                .stream()
                                .map(GroupType::groupName)
                                .collect(Collectors.toSet());

         // look up credential and union in roles
         Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUserId(userId, realm);
         if (ocred.isPresent()) {
            roles.addAll(List.of(ocred.get().getRoles()));
         }

         return roles;


      } catch (Exception e) {
         Log.error(String.format("Failed to get user groups for userId:%s", userId), e);
         return new HashSet<>();
      }
   }

   private Set<String> getUserGroupsForSubject(String subject) {
      return getUserGroupsForSubject(securityUtils.getSystemRealm(), subject);
   }

   private Set<String> getUserGroupsForSubject(String realm, String subject) {
      try {

         Set<String> roles= new HashSet<>();

         // look up credential and union in roles
         Optional<CredentialUserIdPassword> ocred = credentialRepo.findBySubject(subject, realm, true);
         if (ocred.isPresent()) {
            roles.addAll(List.of(ocred.get().getRoles()));
         } else
         {
            throw new NotFoundException("Credential not found for subject: " + subject);
         }


         AdminListGroupsForUserRequest groupsRequest =
            AdminListGroupsForUserRequest.builder()
               .userPoolId(userPoolId)
               .username(ocred.get().getUserId())
               .build();

         AdminListGroupsForUserResponse groupsResponse =
            cognitoClient.adminListGroupsForUser(groupsRequest);

         roles.addAll( groupsResponse
                          .groups()
                          .stream()
                          .map(GroupType::groupName)
                          .collect(Collectors.toSet()));


         return roles;


      } catch (Exception e) {
         Log.error(String.format("Failed to get user groups for subject:%s", subject), e);
         return new HashSet<>();
      }
   }


   private Set<String> getCognitoGroupsForUserIdOnly(String userId) {
      try {
         Set<String> groups = new HashSet<>();
         String nextToken = null;
         do {
            AdminListGroupsForUserRequest.Builder builder = AdminListGroupsForUserRequest.builder()
                                                               .userPoolId(userPoolId)
                                                               .username(userId);
            if (nextToken != null && !nextToken.isEmpty()) {
               builder = builder.nextToken(nextToken);
            }
            AdminListGroupsForUserResponse resp = cognitoClient.adminListGroupsForUser(builder.build());
            if (resp.groups() != null) {
               resp.groups().stream().map(GroupType::groupName).forEach(groups::add);
            }
            nextToken = resp.nextToken();
         } while (nextToken != null && !nextToken.isEmpty());
         return groups;
      } catch (Exception e) {
         e.printStackTrace();
         Log.warnf("Failed to get Cognito groups for userId: %s exception message:%s", userId, e.getMessage());
         return Collections.emptySet();
      }
   }


   @Override
   public Optional<String> getSubjectForUserId (String userId) throws SecurityException {
      return getSubjectForUserId(securityUtils.getSystemRealm(), userId);
   }

   @Override
   public Optional<String> getSubjectForUserId (String realm, String userId) throws SecurityException {
      try {
         // First try local credential repository
         Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUserId(userId, realm, true);
         if (ocred.isPresent() && ocred.get().getSubject() != null && !ocred.get().getSubject().isBlank()) {
            return Optional.of(ocred.get().getSubject());
         }

        if (isCognitoDisabled()) {
           return Optional.empty();
        }

        // Try to resolve via Cognito if available
        Optional<UserType> oUser = retrieveUserId(userId);
        if (oUser.isPresent()) {
           String cognitoUsername = oUser.get().username();
           String sub = fetchSubViaAdminGetUser(cognitoUsername);
           return Optional.ofNullable(sub);
        }
        return Optional.empty();
      } catch (Exception e) {
         Log.errorf(e, "Failed to get subject for userId: %s in realm: %s", userId, realm);
         throw new SecurityException("Failed to get subject for userId: " + e.getMessage(), e);
      }
   }

   @Override
   public Optional<String> getUserIdForSubject (String subject) throws SecurityException {
      return getUserIdForSubject(securityUtils.getSystemRealm(), subject);
   }

   @Override
   public Optional<String> getUserIdForSubject (String realm, String subject) throws SecurityException {
      try {
         Optional<CredentialUserIdPassword> ocred = credentialRepo.findBySubject(subject, realm, true);
         if (ocred.isPresent() && ocred.get().getUserId() != null && !ocred.get().getUserId().isBlank()) {
            return Optional.of(ocred.get().getUserId());
         }
         // Without a credential mapping, we cannot reliably map sub->userId from Cognito; return empty
         return Optional.empty();
      } catch (Exception e) {
         Log.errorf(e, "Failed to get userId for subject: %s in realm: %s", subject, realm);
         throw new SecurityException("Failed to get userId for subject: " + e.getMessage(), e);
      }
   }

   @Override
   public void removeRolesForSubject (String realm, String subject, Set<String> roles) throws SecurityException {
      if (roles == null || roles.isEmpty()) return;
      try {
         Optional<CredentialUserIdPassword> ocred = credentialRepo.findBySubject(subject, realm, true);
         if (!ocred.isPresent()) {
            Log.warnf("removeRolesForSubject: credential not found for subject:%s in realm:%s", subject, realm);
            return;
         }
         String userId = ocred.get().getUserId();
         removeRolesForUserId(userId, roles);
      } catch (Exception e) {
         Log.errorf(e, "Failed to remove roles for subject:%s in realm:%s", subject, realm);
         throw new SecurityException("Failed to remove roles for subject: " + e.getMessage(), e);
      }
   }

   @Override
   public void removeRolesForUserId (String realm, String userId, Set<String> roles) throws SecurityException {
      removeRolesForUserId(userId, roles);
   }
}
