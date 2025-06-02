package com.e2eq.framework.model.security.provider.cognito;

import com.e2eq.framework.exceptions.ReferentialIntegrityViolationException;
import com.e2eq.framework.model.persistent.morphia.CredentialRepo;
import com.e2eq.framework.model.persistent.security.CredentialUserIdPassword;
import com.e2eq.framework.model.persistent.security.DomainContext;
import com.e2eq.framework.model.security.auth.AuthProvider;
import com.e2eq.framework.model.security.auth.UserManagement;

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

import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

/**
 * CognitoAuthProvider is an implementation of AuthProvider and UserManagement interfaces.
 * It provides authentication and user management functionalities using AWS Cognito.
 */
@ApplicationScoped
public class CognitoAuthProvider implements AuthProvider, UserManagement {

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

    /**
     * Constructor for CognitoAuthProvider.
     */
    public CognitoAuthProvider() {
        this.cognitoClient = CognitoIdentityProviderClient.builder().build();
    }

    @Override
    public LoginResponse login(String userId, String password) {
        AdminInitiateAuthRequest authRequest =
            AdminInitiateAuthRequest.builder()
                .userPoolId(userPoolId)
                .clientId(clientId)
                .authFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
                .authParameters(
                    Map.of("USERNAME", userId, "PASSWORD", password)
                )
                .build();

        try {
            AdminInitiateAuthResponse authResponse =
                cognitoClient.adminInitiateAuth(authRequest);
            AuthenticationResultType authResult =
                authResponse.authenticationResult();

            String accessToken = authResult.accessToken();
            String refreshToken = authResult.refreshToken();
            Set<String> groups = getUserGroups(userId);

            SecurityIdentity identity = buildIdentity(userId, groups);
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
            Log.error("Authentication failed for user: " + userId, e);
            throw new SecurityException("Invalid credentials");
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
        Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUsername(username);
        if (!ocred.isPresent()) {
            throw new IllegalStateException(String.format("Credential not configured in database for username: %s  can not resolve username given userid in realm: %s , cognito needs username but it could not be resolved, configure credentials in realm", username , credentialRepo.getDatabaseName()));
        }
        try {
            AdminGetUserRequest request = AdminGetUserRequest.builder()
                .userPoolId(userPoolId)
                .username(ocred.get().getUserId())
                .build();

            cognitoClient.adminGetUser(request);
            return true;
        } catch (UserNotFoundException e) {
            return false;
        } catch (Exception e) {
            Log.error("Error checking user existence", e);
            throw new SecurityException(
                "Failed to check user existence: " + e.getMessage()
            );
        }
    }

    @Override
    public boolean userIdExists(String userId) {

        Optional<CredentialUserIdPassword> ocred = credentialRepo.findByUserId(userId);
        if (!ocred.isPresent()) {
            throw new IllegalStateException("Credential not configured in database for user ID: " + userId + " can not resolve username given userid in realm:" + credentialRepo.getDatabaseName() + ", cognito needs username but it could not be resolved, configure credentials in realm");
        }

        try {
            AdminGetUserRequest request = AdminGetUserRequest.builder()
                                             .userPoolId(userPoolId)
                                             .username(userId)
                                             .build();

            cognitoClient.adminGetUser(request);
            return true;
        } catch (UserNotFoundException e) {
            return false;
        } catch (Exception e) {
            Log.error("Error checking user existence", e);
            throw new SecurityException(
               "Failed to check user existence: " + e.getMessage()
            );
        }
    }

    private SecurityIdentity buildIdentity(String userId, Set<String> roles) {
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

    @Override
    public void createUser(
        String userId,
        String password,
        String username,
        Set<String> roles,
        DomainContext domainContext
    ) throws SecurityException {

       if (!ValidateUtils.isValidEmailAddress(userId)) {
           throw new IllegalArgumentException("UserId should be a valid email address, given: " + userId);
       }

       if (credentialRepo.findByUserId(userId).isPresent()) {
           throw new SecurityException(String.format("User %s already exists in realm: %s",userId, credentialRepo.getDatabaseName()));
       }


        try {
            // Create user in Cognito
            AdminCreateUserRequest createRequest =
                AdminCreateUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .temporaryPassword(password)
                    .messageAction(MessageActionType.SUPPRESS) // Suppress welcome email
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
            Log.info("User Created with username: " + username);
            response.user().attributes().stream().forEach(attr -> {Log.infof("    %s:%s", attr.name(), attr.value());});

            // Set permanent password
            AdminSetUserPasswordRequest passwordRequest =
                AdminSetUserPasswordRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .password(password)
                    .permanent(true)
                    .build();

            cognitoClient.adminSetUserPassword(passwordRequest);

            // Assign roles if provided
            if (!roles.isEmpty()) {
                assignRoles(username, roles);
            }
        } catch (UsernameExistsException e) {
            throw new SecurityException("User already exists: " + username);
        } catch (Exception e) {
            Log.error("Failed to create user", e);
            throw new SecurityException(
                "Failed to create user: " + e.getMessage()
            );
        }
    }

    @Override
    public boolean removeUser(String username)
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
            return false;
        }
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
