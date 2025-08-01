# Quantum Cognito Provider

This module integrates the Quantum framework with AWS Cognito using Quarkus. It provides authentication and user management features and includes tests that exercise the Cognito integration.

## Required environment variables

The following environment variables configure the Cognito and MongoDB settings used by the application and tests. When running the tests with real AWS access, these values must point to your Cognito user pool and other resources.

- `APPLICATION_CLIENT_ID` – Cognito application client ID.
- `USER_POOL_ID` – Cognito user pool ID.
- `AWS_REGION` – AWS region where the user pool resides.
- `QUARKUS_HTTP_CORS_ORIGINS` – Allowed CORS origins for the HTTP server.
- `JWT_SECRET` – Secret used to sign JWTs during tests.
- `MONGODB_CONNECTION_STRING` – Mongo connection string (defaults to a local instance).
- `MONGODB_DEFAULT_SCHEMA` – Default MongoDB schema name.

Other MongoDB helper variables used in the connection string are `MONGODB_USERNAME`, `MONGODB_PASSWORD`, `MONGODB_HOST` and `MONGODB_DATABASE`.

## .env file

Create a `.env` file in the project root and populate it with the variables above. Example:

```dotenv
APPLICATION_CLIENT_ID=app-client-id
USER_POOL_ID=us-east-1_example
AWS_REGION=us-east-1
QUARKUS_HTTP_CORS_ORIGINS=http://localhost:3000
JWT_SECRET=change-me
MONGODB_CONNECTION_STRING=mongodb://localhost:27017/?retryWrites=false
MONGODB_DEFAULT_SCHEMA=system-com
AUTH_PROVIDER=cognito
```

Load the file before running Maven so that the variables are available:

```bash
source .env
mvn test
```

## Running tests without Cognito

If you do not want the tests to connect to AWS, set `AUTH_PROVIDER` to any value other than `cognito` before running the tests:

```bash
AUTH_PROVIDER=disabled mvn test
```

## Notes on test execution

When `APPLICATION_CLIENT_ID`, `USER_POOL_ID` and `AWS_REGION` are supplied (either directly or through `.env`), the tests connect to the specified Cognito user pool to create users and validate tokens.

This project uses Quarkus with AWS Cognito. Configuration is supplied via environment variables.

1. Copy `.env.example` to `.env`.
2. Edit `.env` and provide real values for your environment.

The provided `.env.example` includes common variables such as `QUARKUS_HTTP_CORS_ORIGINS`, `APPLICATION_CLIENT_ID`, `USER_POOL_ID`, and `AWS_REGION` that must be set for the application to run.

