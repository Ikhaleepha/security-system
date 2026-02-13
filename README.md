# Security System - JWT Authentication & Authorization

A multi-module Spring Boot project implementing JWT-based authentication and authorization as a reusable starter library.

## Project Structure

```
security-system/
├── core-security-starter/     # Reusable Spring Boot starter library
│   └── com.mam/
│       ├── config/            # Auto-configuration, Security config
│       ├── exception/         # Custom exceptions, global handler
│       ├── filter/            # JWT filter, entry point, access denied handler
│       ├── model/             # DTOs (AuthRequest, AuthResponse, JwtUserDetails)
│       └── service/           # JwtTokenService
└── application/               # Sample application consuming the starter
    └── com.mam.app/
        ├── controller/        # REST endpoints
        ├── entity/            # User entity
        ├── repository/        # UserRepository
        └── service/           # UserDetailsService, AuthenticationService
```

## Prerequisites

- Java 21
- Maven 3.8+

## Build & Run

### Build all modules
```bash
./mvnw clean install
```

### Run the application
```bash
./mvnw spring-boot:run -pl application
```

The application starts on `http://localhost:8080`

### Run tests
```bash
./mvnw test
```

## API Endpoints

| Endpoint | Method | Auth Required | Role Required |
|----------|--------|---------------|---------------|
| `/api/public/health` | GET | No | - |
| `/api/auth/login` | POST | No | - |
| `/api/user/me` | GET | Yes | Any authenticated |
| `/api/admin/users` | GET | Yes | ROLE_ADMIN |

## Demo Users

| Username | Password | Roles |
|----------|----------|-------|
| user | password | ROLE_USER |
| admin | password | ROLE_USER, ROLE_ADMIN |

## Example Requests

### Health Check (Public)
```bash
curl http://localhost:8080/api/public/health
```

Response:
```json
{"status": "UP", "timestamp": "2024-01-15T10:30:00Z"}
```

### Login
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "password"}'
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "tokenType": "Bearer",
  "expiresIn": 86400,
  "username": "user",
  "roles": ["ROLE_USER"]
}
```

### Get Current User (Authenticated)
```bash
curl http://localhost:8080/api/user/me \
  -H "Authorization: Bearer <token>"
```

Response:
```json
{
  "userId": 1,
  "username": "user",
  "roles": ["ROLE_USER"]
}
```

### Get All Users (Admin Only)
```bash
curl http://localhost:8080/api/admin/users \
  -H "Authorization: Bearer <admin-token>"
```

Response:
```json
[
  {"id": 1, "username": "user", "roles": "ROLE_USER", "enabled": true},
  {"id": 2, "username": "admin", "roles": "ROLE_USER,ROLE_ADMIN", "enabled": true}
]
```

### Error Responses

**401 Unauthorized:**
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "status": 401,
  "error": "Unauthorized",
  "message": "Authentication required",
  "path": "/api/user/me"
}
```

**403 Forbidden:**
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "status": 403,
  "error": "Forbidden",
  "message": "Insufficient permissions",
  "path": "/api/admin/users"
}
```

## Configuration Properties

Configure the JWT settings in `application.yml`:

```yaml
mam:
  security:
    jwt:
      secret: <base64-encoded-256-bit-key>
      expiration-ms: 86400000  # 24 hours
      issuer: my-application
```

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `mam.security.jwt.secret` | String | (required) | Base64-encoded secret key (min 256 bits) |
| `mam.security.jwt.expiration-ms` | Long | 86400000 | Token validity in milliseconds |
| `mam.security.jwt.issuer` | String | mam-security | JWT issuer claim |

## Design Decisions

### Architecture
- **Multi-module design**: The `core-security-starter` is a standalone library that can be reused across projects. The `application` module demonstrates consumption.
- **Spring Boot Auto-configuration**: Uses `@AutoConfiguration` with conditional beans for seamless integration.
- **Stateless JWT**: No server-side session storage; all authentication state is in the token.

### Security
- **BCrypt password hashing**: Industry-standard password encoding with configurable work factor.
- **HS256 signing**: JWT tokens signed with HMAC-SHA256.
- **Role-based authorization**: URL-level rules in SecurityFilterChain + method-level with `@PreAuthorize`.

### Cross-cutting Concerns (in core-security-starter)
- **JWT Filter**: Extracts and validates tokens, sets SecurityContext.
- **Exception Handling**: Global handler for 401/403 with consistent error format.
- **Logging**: Logs authenticated user and endpoint on each request.
- **Configuration**: Externalized via `@ConfigurationProperties`.

### Trade-offs
- **In-memory H2**: Demo uses H2 for simplicity. Production should use persistent database.
- **Simple role storage**: Roles stored as comma-separated string. Production might use separate table.
- **No refresh tokens**: Tokens expire after configured time. Could add refresh token flow for production.
