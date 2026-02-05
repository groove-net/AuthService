# AuthService

A robust, pluggable authentication engine designed for modern distributed systems. This project implements a secure identity lifecycle—from registration and multi-factor authentication (MFA) to account recovery and session management—while remaining infrastructure-agnostic.

## 🏗 Architecture & Design

The project follows a **Clean Architecture** approach to ensure that business rules (Domain) are isolated from external concerns (Infrastructure/Web).

- **Domain Layer:** Contains the `User` Aggregate Root, Seedwork (Entity, ValueObject, Result pattern), and business invariants (MFA logic, PBKDF2 hashing).
- **Application Layer:** Implements the **Command/Query pattern** through Use Cases. Each Use Case (e.g., `RegisterUser`, `Verify2fa`) is a single-responsibility class that orchestrates the domain logic.
- **Infrastructure Layer:** Handles persistence via Entity Framework Core and implements security interfaces (Data Protection, JWT Generation).
- **Web API:** A thin REST wrapper using **FastEndpoints** to expose the application logic via a highly performant, vertical-slice-based API.

---

## 🔐 Security Features

- **PBKDF2 Hashing:** Secure password hashing with unique salts and configurable iterations ($150,000+$).
- **Multi-Factor Authentication (TOTP):** Full enrollment flow with QR code generation, recovery codes, and replay protection.
- **Stateless & Stateful Tokens:** * **Email Confirmation:** Stateless tokens using `IDataProtector`.
    - **Password Resets:** Stateful tokens using SHA256 hashing in the database.
- **JWT & Refresh Tokens:** Self-managed session management with `SecurityStamp` validation for global account logout.
- **Rate Limiting & Lockout:** Protection against brute-force attacks at both the password and 2FA stages.

---

## 🚀 Getting Started

### Prerequisites

- .NET 8.0 SDK
- SQL Server (or your preferred EF Core provider)

### Installation

1. **Clone the repository:**
    
    ```bash
    git clone https://github.com/your-repo/AuthService.git
    cd AuthService
    ```
    
2. **Restore dependencies:**Bash
    
    ```bash
    dotnet restore
    ```
    
3. **Update Database:**Bash
    
    Ensure your connection string is set in `appsettings.json`, then run:
    
    ```bash
    dotnet ef database update
    ```
    

---

## 🛠 Usage

### Integrating the Auth Component

The project exposes an `AuthComponent` static gateway (or DI-injected service) that simplifies the interaction for host applications.

```bash
// Example: Registering a new user
var result = await AuthComponent.RegisterUser(
    "gabriel_dev", 
    "gabriel@example.com", 
    "P@ssw0rd123!"
);

if (result.IsSuccess) 
{
    // Handle success (e.g., redirect to email confirmation page)
}
```

### Identity Propagation (Service-to-Service)

Downstream services (Service B, C) do not need the full Auth library. They simply validate the JWT signature locally using shared keys.

---

## 📁 Folder Structure

```bash
src/Auth/
├── Domain/                 # Enterprise Business Rules
│   ├── Aggregates/         # User Aggregate & Entities
│   └── Seedwork/           # Base classes (Entity, ValueObject)
├── Application/            # Application Business Rules
│   ├── UseCases/           # Login, Register, MFA logic
│   └── Interfaces/         # Repository & Service contracts
├── Infrastructure/         # External Tools & Persistence
│   ├── Persistence/        # EF Core DbContext & Repositories
│   └── Security/           # JWT & Data Protection implementations
└── WebAPI.REST/            # Delivery Layer
    └── Endpoints/          # FastEndpoints (POST Login, GET Setup2fa)
```

---

## 📜 Key Use Cases

- **Authentication:** `UserLogin`, `Verify2fa`, `UseRecoveryCode`
- **Management:** `RegisterUser`, `ConfirmEmail`, `Setup2fa`, `Disable2fa`
- **Recovery:** `EmailPasswordResetToken`, `ValidatePasswordResetToken`

---

## ⚖️ License

This project is licensed under the MIT License.
