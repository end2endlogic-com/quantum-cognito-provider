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

        AdminInitiateAuthRequest authRequest =
            AdminInitiateAuthRequest.builder()
                .userPoolId(userPoolId)
                .clientId(clientId)
                .authFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
                .authParameters(
                    Map.of("USERNAME", ocred.get().getUsername(), "PASSWORD", password)
                )
                .build();

        try {
            AdminInitiateAuthResponse authResponse =
                cognitoClient.adminInitiateAuth(authRequest);
            AuthenticationResultType authResult =
                authResponse.authenticationResult();

            String accessToken = authResult.accessToken();
            String refreshToken = authResult.refreshToken();
            Set<String> groups = getUserGroups(ocred.get().getUsername());
            groups.addAll(Set.of(ocred.get().getRoles()));

            SecurityIdentity identity = buildIdentity(ocred.get().getUserId(), groups);
            securityIdentityAssociation.setIdentity(identity);

            return new LoginResponse(
                true,
                new LoginPositiveResponse(
                    userId,
                    identity,
                    groups,
                    accessToken,
                    refreshToken,
                    new Date(
                        TokenUtils.currentTimeInSecs() + durationInSeconds
                    ).getTime()
                )
            );
        } catch (NotAuthorizedException e) {
            Log.error("Authentication failed for userId: " + userId, e);
            throw new SecurityException("Invalid credentials");
        } catch (UserNotFoundException e) {
            Log.error("User not found: " + userId, e);
            throw e;
        }
        catch (Exception e) {
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

        return new LoginResponse(
            true,
            new LoginPositiveResponse(
                username,
                identity,
                groups,
                newIdToken,
                newRefreshToken,
                new Date(
                    TokenUtils.currentTimeInSecs() + durationInSeconds
                ).getTime()
            )
        );
    }

    @Override
    public boolean usernameExists(String username) {
      return usernameExists(securityUtils.getSystemRealm(), username);
    }

   @Override
   public boolean usernameExists (String realm, String username) throws SecurityException {

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
        Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUsername(username);
        if (!ocred.isPresent()) {
            throw new IllegalStateException(
                String.format(
                    "Credential not configured in database for username: %s cannot resolve Cognito username in realm: %s",
                    username,
                    credentialRepo.getDatabaseName()
                )
            );
        }
        try {
            String cognitoUsername = ocred.get().getUsername();
            AdminGetUserRequest request =
                AdminGetUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(cognitoUsername)
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
      //return userIdExists(userId);
      // We are being given a userId and we need to now translate this to a username.  The only way we can do that is via the credential collection
      // however if the credential database does not have it / has not been set up then we either throw an exception to this effect or we lie and say its not
      // I choose to throw an exception to the caller.
      Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUserId(userId, realm);
      if (!ocred.isPresent()) {
         Log.warnf("Credential not configured in database for userid: %s  can not resolve username given userid in realm: %s, cognito needs username but it could not be resolved, configure credentials in realm", userId, realm);
         return false;
      }

      AdminGetUserRequest request = AdminGetUserRequest.builder()
                                       .userPoolId(userPoolId)
                                       .username(ocred.get().getUserId())
                                       .build();
      try {
         cognitoClient.adminGetUser(request);
      } catch (UserNotFoundException e) {
         Log.warn(e.getMessage());
         return false;
      }
      return true;
   }
            cognitoClient.adminGetUser(request);
            return true;
        } catch (UserNotFoundException e) {
            return false;
        } catch (Exception e) {
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
    public boolean userIdExists(String userId) {
         return userIdExists(securityUtils.getSystemRealm(), userId);
    }

        Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUserId(userId);
        if (!ocred.isPresent()) {
            throw new IllegalStateException(
                "Credential not configured in database for user ID: " +
                userId +
                " cannot resolve Cognito username in realm:" +
                credentialRepo.getDatabaseName()
            );
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
    public void createUser (String realm, String userId, String password, Boolean forceChangePassword, String username, Set<String> roles, DomainContext domainContext) throws SecurityException {
        Log.infof("Creating userId:%s, username:%s, roles:%s, domainContext:%s in realm:%s", userId, username, roles, domainContext, realm);

        if (!ValidateUtils.isValidEmailAddress(userId)) {
            throw new IllegalArgumentException("UserId should be a valid email address, given: " + userId);
        }


        try {
            String cognitoUsername = ocred.get().getUsername();
            AdminGetUserRequest request =
                AdminGetUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(cognitoUsername)
                    .build();
            Log.infof("Checking userId:%s in cognito", userId);
            // check if user already exists in cognito
            if (!this.userIdExists(realm, userId)) {
                Log.infof("User does not exist in cognito, creating user with userId:%s and username:%s", userId, username);
                // Create user in Cognito
                AdminCreateUserRequest createRequest =
                   AdminCreateUserRequest.builder()
                      .userPoolId(userPoolId)
                      .username(userId) // because cognito could be configured to only accept email addresses as the username not a guid
                      .temporaryPassword(password)
                      .messageAction(forceChangePassword == null ? MessageActionType.SUPPRESS : MessageActionType.RESEND) // Suppress welcome email
                      .userAttributes(
                         AttributeType.builder()
                            .name("email")
                            .value(userId)
                            .build(),
                         AttributeType.builder()
                            .name("email_verified")
                            .value("true")
                            .build()
                      )
                      .build();

                AdminCreateUserResponse response = cognitoClient.adminCreateUser(createRequest);
                if (!response.sdkHttpResponse().isSuccessful()) {
                    throw new SecurityException(
                       "Failed to create user: " + response.toString()
                    );
                }
                Log.info("User Created with username: " + response.user().username());
                username = response.user().username();

                // Set permanent password
                AdminSetUserPasswordRequest passwordRequest =
                   AdminSetUserPasswordRequest.builder()
                      .userPoolId(userPoolId)
                      .username(userId)
                      .password(password)
                      .permanent(forceChangePassword == null ? true : false)
                      .build();

                AdminSetUserPasswordResponse pwResponse = cognitoClient.adminSetUserPassword(passwordRequest);

                // Assign roles if provided
                if (!roles.isEmpty()) {
                    assignRoles(userId, roles);
                }
            } else {
                Log.warnf("UserId %s already exists in cognito, skipping creation", userId);
            }

            Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUserId( userId, realm);

            if (ocred.isPresent()) {
                Log.debug("User already exists in the credentials database, checking configuration");
                if (!ocred.get().getUsername().equals(username) && ocred.get().getPasswordHash().equals(EncryptionUtils.hashPassword(password)) &&
                       ocred.get().getDomainContext().equals(domainContext) && new HashSet<>(List.of(ocred.get().getRoles())).containsAll(roles)) {
                    throw new SecurityException(String.format("User %s already exists in realm: %s with different configuration check database", userId, credentialRepo.getDatabaseName()));
                } else {
                    Log.warnf("User %s already exists in realm: %s with same configuration, skipping  credential creation", userId, credentialRepo.getDatabaseName());
                }
            } else {
                Log.info("User does not exist in the credentials database, creating credentials");
                CredentialUserIdPassword credential = new CredentialUserIdPassword();
                credential.setRefName(username);
                credential.setUserId(userId);
                credential.setUsername(username);
                credential.setPasswordHash(EncryptionUtils.hashPassword(password));
                credential.setDomainContext(domainContext);
                credential.setRoles(roles.toArray(new String[roles.size()]));
                credential.setLastUpdate(new Date());
                credential = credentialRepo.save(realm, credential);
                Log.infof("Credential created with username:%s userId:%s in realm:%s", username, userId, realm);

            }
        } catch (UsernameExistsException e) {
            throw new SecurityException(String.format("User with username:%s already exists in cognito: msg:%s ",username, e.getMessage()));
        } catch (Exception e) {
            Log.error("Failed to create user", e);
            throw new SecurityException(
               "Failed to create user: " + e.getMessage()
            );
        }

    }

    @Override
    public boolean removeUserWithUsername (String realm, String username) throws ReferentialIntegrityViolationException {
        return removeUserWithUsername(username);
    }
   @Override
   public boolean removeUserWithUsername(String username)
      throws ReferentialIntegrityViolationException {
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

         AdminDeleteUserResponse response =  cognitoClient.adminDeleteUser(deleteRequest);
         if (!response.sdkHttpResponse().isSuccessful()) {
            Log.warnf("remove username %s  failed with message: %s", username, response.sdkHttpResponse().statusText().orElse(""));
            return false;
         } else {
            Log.infof("remove username %s  successful", username);
            return true;
        } catch (UserNotFoundException e) {
            return false;
        } catch (Exception e) {
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
      } catch (UserNotFoundException e) {
         Log.warnf("Username %s could not be found", username);
         return false;
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
        return getUserGroups(username);
    }


}
