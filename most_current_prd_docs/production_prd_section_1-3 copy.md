# **PRODUCTION-READY PRODUCT REQUIREMENTS DOCUMENT (PRD) SECTIONS 1 - 3**
## Product Requirements Document (Conflict-Resolved Version)
### PRD version with "patch" sections added by CLINE

**Document Version:** 7.1.3 FINAL PRODUCTION READY VERSION
**Last Updated:** October, 17 2025
**Status:** Approved for Development

## Table of Contents

1. [Introduction & Overview](#1-introduction--overview)
2. [🔴🟢🟡 Test-Driven Development (TDD) - CRITICAL CORNERSTONE](#2-test-driven-development-tdd---critical-cornerstone)
3. [System Architecture](#3-system-architecture)
4. [User Roles & Workflow](#4-user-roles--workflow)
5. [API Integrations](#5-api-integrations)
6. [Complete Customer Journey - Single Source of Truth](#6-complete-customer-journey---single-source-of-truth)
7. [Digital DNA System - Invisible Security Validation](#7-digital-dna-system---invisible-security-validation)
8. [Security Alert System](#8-security-alert-system)
9. [Security Implementation](#9-security-implementation)
10. [Database Schema](#10-database-schema)
11. [Federal Compliance](#11-federal-compliance)
12. [Error Handling](#12-error-handling)
13. [Implementation Standards](#13-implementation-standards)
14. [Production Deployment Checklist](#14-production-deployment-checklist)
15. [Conclusion](#15-conclusion)

---

## 1. Introduction & Overview

### 1.1. Product Summary

The **WP Admin Dashboard Optimizer Plugin** enables secure gift card liquidation through integrated payment processing and bank transfers. The system uses **Plaid OAuth 2.0** for bank account linking and **Authorize.Net** for payment processing, with strict federal compliance and multi-layer security validation.

### 1.2. Core Value Proposition

- **Instant Gift Card Liquidation**: Convert gift cards to cash in real-time
- **Federal Compliance**: Automated limit enforcement per regulatory requirements
- **Bank-Grade Security**: AES-256 encryption, OAuth 2.0, multi-stage validation
- **Seamless Integration**: Native WordPress implementation with custom roles

### 1.3. Key Features

- Progressive user role system with automatic transitions
- Real-time payment processing via RTP/FedNow
- Comprehensive audit logging and reconciliation
- Admin dashboard with transaction monitoring and **Real-Time metrics** (see §13.4)
- Automated error handling and retry mechanisms

---

## 2. 🔴🟢🟡 Test-Driven Development (TDD) - CRITICAL CORNERSTONE

**ALL CODE MUST FOLLOW TDD PROCESS:**
1. 🔴 **RED**: WRITE FAILING TEST FIRST
2. 🟢 **GREEN**: IMPLEMENT MINIMAL CODE TO PASS / ***DO NOT HARD CODE TEST RESULTS SO THE TEST PASSES!***
3. 🟡 **REFACTOR**: CLEAN CODE WHILE MAINTAINING ALL PREVIOUSLY SUCCESSFUL TESTS

### 2.1. Required Test Coverage

```php
// Example Unit Test Structure
class TransactionManagerTest extends WP_UnitTestCase {

    public function test_federal_limits_block_excessive_amounts() {
        // ARRANGE
        $user_id = $this->factory->user->create();
        $limit_manager = new LimitManager();

        // Create existing transactions totaling $400
        $this->create_test_transactions($user_id, 400);

        // ACT & ASSERT
        $result = $limit_manager->check_federal_limits($user_id, 200); // Would exceed $500/24h

        $this->assertWPError($result);
        $this->assertEquals('limit_exceeded', $result->get_error_code());
    }

    public function test_encryption_decrypt_consistency() {
        // ARRANGE
        $encryption_manager = new EncryptionManager();
        $test_data = 'sensitive_token_123';

        // ACT
        $encrypted = $encryption_manager->encrypt($test_data);
        $decrypted = $encryption_manager->decrypt($encrypted);

        // ASSERT
        $this->assertEquals($test_data, $decrypted);
        $this->assertNotEquals($test_data, $encrypted);
    }

    public function test_role_transition_with_expiry() {
        // ARRANGE
        $user_id = $this->factory->user->create();
        $role_manager = new RoleManager();

        // ACT
        $result = $role_manager->transition_user_role($user_id, RoleManager::ROLE_PLAID_USER);

        // ASSERT
        $this->assertTrue($result);
        $user = new WP_User($user_id);
        
        // WordPress Best Practice: User should have BOTH subscriber and progressive role
        $this->assertTrue($user->has_role(RoleManager::ROLE_SUBSCRIBER), 'User must maintain subscriber base role');
        $this->assertTrue($user->has_role(RoleManager::ROLE_PLAID_USER), 'User must have progressive role');

        // Check expiry is set
        $expiry = get_user_meta($user_id, 'cfmgc_role_expiry', true);
        $this->assertGreaterThan(time(), $expiry);
    }

    public function test_fee_calculation_accuracy() {
        // ARRANGE
        $transaction_amount = 100.00;
        $expected_payout = 83.50; // $100 - (15% + $1.50) = $83.50

        // ACT
        $calculated_payout = $transaction_amount - (($transaction_amount * 15 / 100) + 1.50);

        // ASSERT
        $this->assertEquals($expected_payout, $calculated_payout);
    }

    public function test_plaid_access_token_encrypted_round_trip() {
        $user_id = $this->factory->user->create();
        $enc = new EncryptionManager();

        $plain = 'access-sample';
        update_user_meta($user_id, 'cfmgc_plaid_access_token', $enc->encrypt($plain));

        $stored = get_user_meta($user_id, 'cfmgc_plaid_access_token', true);
        $this->assertNotEquals($plain, $stored, 'Token must not be stored in plaintext');
        $this->assertEquals($plain, $enc->decrypt($stored), 'Decryption must match original');
    }

    public function test_plaid_user_gate_transitions_to_transaction_user() {
        $user_id = $this->factory->user->create();
        $roles = new RoleManager();
        $roles->transition_user_role($user_id, RoleManager::ROLE_PLAID_USER);

        // Simulate orchestrator success
        (new RoleManager())->transition_user_role($user_id, RoleManager::ROLE_TRANSACTION_USER);

        $user = new WP_User($user_id);
        $this->assertTrue(in_array(RoleManager::ROLE_TRANSACTION_USER, (array)$user->roles, true));
    }

    public function test_wordpress_compliant_role_management() {
        // ARRANGE
        $user_id = $this->factory->user->create();
        $role_manager = new RoleManager();

        // ACT & ASSERT: Test progressive role transitions maintain subscriber
        
        // Step 1: Add Plaid User role
        $role_manager->transition_user_role($user_id, RoleManager::ROLE_PLAID_USER);
        $user = new WP_User($user_id);
        $this->assertTrue($user->has_role(RoleManager::ROLE_SUBSCRIBER), 'Subscriber role must persist');
        $this->assertTrue($user->has_role(RoleManager::ROLE_PLAID_USER), 'Progressive role must be added');
        $this->assertFalse($user->has_role(RoleManager::ROLE_TRANSACTION_USER), 'Other progressive roles must not exist');

        // Step 2: Transition to Transaction User
        $role_manager->transition_user_role($user_id, RoleManager::ROLE_TRANSACTION_USER);
        $user = new WP_User($user_id);
        $this->assertTrue($user->has_role(RoleManager::ROLE_SUBSCRIBER), 'Subscriber role must persist');
        $this->assertTrue($user->has_role(RoleManager::ROLE_TRANSACTION_USER), 'New progressive role must be added');
        $this->assertFalse($user->has_role(RoleManager::ROLE_PLAID_USER), 'Previous progressive role must be removed');

        // Step 3: Transition to PAYMENT
        $role_manager->transition_user_role($user_id, RoleManager::ROLE_PAYMENT);
        $user = new WP_User($user_id);
        $this->assertTrue($user->has_role(RoleManager::ROLE_SUBSCRIBER), 'Subscriber role must persist');
        $this->assertTrue($user->has_role(RoleManager::ROLE_PAYMENT), 'New progressive role must be added');
        $this->assertFalse($user->has_role(RoleManager::ROLE_TRANSACTION_USER), 'Previous progressive role must be removed');

        // Step 4: Revert to Subscriber only
        $role_manager->transition_user_role($user_id, RoleManager::ROLE_SUBSCRIBER);
        $user = new WP_User($user_id);
        $this->assertTrue($user->has_role(RoleManager::ROLE_SUBSCRIBER), 'Subscriber role must persist');
        $this->assertFalse($user->has_role(RoleManager::ROLE_PAYMENT), 'Progressive role must be removed');
        
        // Verify only subscriber role remains
        $this->assertEquals(['subscriber'], $user->roles, 'Only subscriber role should remain');
    }
}
```

---

## 3. System Architecture

### 3.1. High-Level Architecture

```mermaid
graph TB

A[WordPress Frontend] --> B[WS Form PRO]

B --> C[Federal Limit Check]

C --> R1[Role: Subscriber → Plaid User]

R1 --> D[Plaid Link OAuth]

D --> E[RTP Capability Check]

E --> F[Identity Match]

F --> R2[Role: Plaid User → Transaction User]

R2 --> H[WS Form Authorize.Net Button\n(WS Form add-on)]

H --> R3[Role: Transaction User → PAYMENT]

R3 --> J[Payout via Plaid RTP/FedNow]

J --> R4[Role: PAYMENT → Subscriber]
```

The payment box explicitly sits under WS Form. No custom Accept.js.

### 3.2. Component Directory Structure

```
wp-admin-dashboard-optimizer/  // Root plugin directory (slug). Production-ready, no-new-files architecture aligned to PRD & journey.  [oai_citation:0‡10:9_prd.md](file-service://file-DgGp7WivSJ8BKukuZzfJc1)
│
├── wp-admin-dashboard-optimizer.php            // Main plugin loader: headers, constants, Composer autoload, providers bootstrap, activation/deactivation hooks
├── uninstall.php                               // Multisite-aware, idempotent cleanup; honors data-retention constant; drops tables only when allowed
├── readme.txt                                  // WP.org-style readme for distribution
├── LICENSE                                     // License
├── composer.json                               // PSR-4 autoload ("CFMGC\\WPADO\\"); scripts: phpcs, phpstan, phpunit, make-pot
├── phpunit.xml.dist                            // PHPUnit config (unit+integration suites, coverage)
├── package.json                                // JS build/lint/test scripts (wp-scripts/Vite, make-pot, playwright)
├── vite.config.js                              // Optional modern build config for ES modules
├── .editorconfig                               // Consistent whitespace/EOLs (tabs for PHP)
├── .gitignore                                  // Ignore vendor, node_modules, build artifacts
├── .gitattributes                              // Normalized line endings, linguist hints
├── phpcs.xml                                   // WordPress Coding Standards ruleset
├── phpstan.neon.dist                           // Static analysis config
├── .eslintignore                               // JS lint ignores
├── .eslintrc.json                              // JS lint rules
├── .stylelintrc.json                           // CSS lint rules
│
├── languages/                                  // i18n/l10n assets for PHP and JS
│   ├── wp-admin-dashboard-optimizer.pot        // Translation template (PHP)
│   └── wp-admin-dashboard-optimizer-js.json    // Script translations (wp_set_script_translations)
│
├── src/                                        // PSR-4 namespaced source code (testable, modular)
│   ├── Core/                                   // Startup orchestration & provider system (keeps boot logic cohesive)
│   │   ├── Plugin.php                          // Registers providers, loads textdomain, privacy hooks, wiring
│   │   ├── Bootstrap.php                       // Env checks, constants/defaults, graceful bailouts
│   │   ├── ServiceContainer.php                // Lightweight DI container (bind/get/singleton)
│   │   └── Providers/                          // Modular service registration (admin, rest, db, security, jobs, cli, i18n)
│   │       ├── AdminServiceProvider.php
│   │       ├── RestServiceProvider.php
│   │       ├── IntegrationServiceProvider.php
│   │       ├── DatabaseServiceProvider.php
│   │       ├── SecurityServiceProvider.php
│   │       ├── JobsServiceProvider.php
│   │       ├── CliServiceProvider.php
│   │       └── I18nServiceProvider.php
│   │
│   ├── Config/                                 // Config samples, capabilities map, feature flags
│   │   ├── config.dist.php
│   │   ├── capabilities.php
│   │   └── features.php
│   │
│   ├── Domain/                                 // Business/domain logic (roles, limits, payouts, transactions)
│   │   ├── Entities/
│   │   │   ├── Transaction.php
│   │   │   ├── Payout.php
│   │   │   └── UserSession.php
│   │   ├── Services/
│   │   │   ├── RoleManager.php                 // "Subscriber + one progressive role" with expirations
│   │   │   ├── LimitManager.php                // Federal limits calculations & preflight
│   │   │   ├── TransactionManager.php          // Create/commit transactions via repositories
│   │   │   ├── PayoutManager.php               // RTP/FedNow initiation, retries, reconciliation
│   │   │   └── OfferCalculator.php             // Server-side payout offer math (15% + $1.50)
│   │   └── Interfaces/
│   │       ├── RepositoryInterface.php
│   │       ├── PayoutProviderInterface.php
│   │       └── LoggerInterface.php
│   │
│   ├── Integration/                            // External systems with strict trust boundaries
│   │   ├── WSForm/                             // WS Form (and ANet add-on) success-only listeners; no PAN/Accept.js
│   │   │   ├── Compatibility.php               // Guarded hooks + admin notice if missing
│   │   │   ├── PaymentSuccessListener.php      // Transitions to PAYMENT after WS Form reports success
│   │   │   └── Extractors.php                  // Safe extraction of submission meta (cart total, ids)
│   │   ├── AuthorizeNet/                       // Authorize.Net validations (no payment processing here)
│   │   │   └── WebhookValidator.php            // HMAC-SHA512 verification (if used)
│   │   └── Plaid/                              // Plaid OAuth 2.0, identity, capabilities, webhooks
│   │       ├── Client.php
│   │       ├── OAuth.php
│   │       ├── LinkHandler.php
│   │       └── WebhookController.php           // ES256 JWT + body-hash + replay checks
│   │
│   ├── Security/                               // Centralized security utilities & controls
│   │   ├── EncryptionManager.php               // AES-256-CBC, IV handling, rotation plan
│   │   ├── ValidationManager.php               // SC1–SC5 secret validations
│   │   ├── DigitalDNA/                         // Invisible session correlation system (cache-first + DB fallback)
│   │   │   ├── DNAService.php
│   │   │   └── SessionStore.php
│   │   ├── WebhookReplayGuard.php              // Event id/timestamp cache to block replays
│   │   ├── Nonce.php                           // AJAX/REST nonce helpers
│   │   └── RateLimiter.php                     // Token-bucket limiter for sensitive endpoints
│   │
│   ├── REST/                                   // WordPress REST API layer with explicit JSON Schemas
│   │   ├── Routes.php                          // Registers namespace "cfmgc/v1"
│   │   ├── Permissions.php                     // permission_callback helpers (caps + nonces)
│   │   ├── Controllers/
│   │   │   ├── LimitsController.php            // GET /limits/check
│   │   │   ├── MetricsController.php           // GET /metrics/live (30s cache)
│   │   │   ├── PlaidWebhookController.php      // POST /plaid/webhook (raw body verify)
│   │   │   └── HealthController.php            // GET /health
│   │   └── Schemas/                            // JSON Schemas (stable contracts for clients & tests)
│   │       ├── limits-response.json
│   │       ├── metrics-response.json
│   │       └── webhook-event.json
│   │
│   ├── Admin/                                  // Admin UI (Screen API, widgets, notices, a11y)
│   │   ├── Screens/
│   │   │   ├── Dashboard.php                   // Today’s Metrics, Live Feed, Alerts
│   │   │   ├── Settings.php                    // Settings API for env/flags/retention/logging
│   │   │   └── Tools.php                       // Migrations, cache clear, webhook test
│   │   ├── Widgets/
│   │   │   └── FederalLimitWidget.php          // Visualizes remaining federal limits
│   │   ├── ListTables/
│   │   │   └── Transactions_List_Table.php     // Paginated/filtered transactions list
│   │   ├── Notices.php                         // Centralized admin notices (a11y)
│   │   └── Assets/
│   │       ├── admin.js
│   │       ├── admin.css
│   │       └── accessibility.css
│   │
│   ├── Public/                                 // Front-end presentation (shortcodes/blocks/assets)
│   │   ├── Shortcodes/
│   │   │   └── LimitStatusShortcode.php        // [wpado_limit_status] preflight UI
│   │   ├── Blocks/
│   │   │   └── federal-limit-status/
│   │   │       ├── block.json
│   │   │       ├── edit.js
│   │   │       └── style.css
│   │   └── Assets/
│   │       ├── limit-widget.js                 // Nonce + REST fetch; aria-live updates
│   │       └── limit-widget.css
│   │
│   ├── Database/                               // Schema, migrations, repositories, upgrader
│   │   ├── Repositories/
│   │   │   ├── TransactionsRepository.php
│   │   │   ├── PayoutsRepository.php
│   │   │   ├── UserActivityRepository.php
│   │   │   └── SystemEventsRepository.php
│   │   ├── Schema/
│   │   │   ├── Tables.php                      // Table names, columns, prefixes
│   │   │   └── dbDeltaSql.php                  // SQL strings for dbDelta
│   │   ├── Migrations/
│   │   │   ├── 2025_01_01_000001_create_transactions.php
│   │   │   ├── 2025_01_01_000002_create_error_logs.php
│   │   │   ├── 2025_01_01_000003_create_payout_log.php
│   │   │   ├── 2025_01_01_000004_create_user_activity.php
│   │   │   ├── 2025_01_01_000005_create_system_events.php
│   │   │   └── 2025_01_01_000006_create_sessions_fallback.php
│   │   ├── Seeds/
│   │   │   └── DemoDataSeeder.php
│   │   └── Upgrader.php                        // Versioned upgrades & legacy table migration
│   │
│   ├── Jobs/                                   // Scheduled maintenance & retry jobs
│   │   ├── Schedules.php                       // Registers cron schedules/events
│   │   ├── CleanupExpiredRolesJob.php
│   │   ├── RetryPayoutJob.php
│   │   └── ArchiveOldLogsJob.php
│   │
│   ├── CLI/                                    // WP-CLI commands for ops/devex
│   │   ├── Register.php
│   │   ├── MigrateCommand.php
│   │   ├── RolesCommand.php
│   │   └── PayoutCommand.php
│   │
│   ├── Performance/                            // Perf helpers & cache strategies
│   │   ├── Cache.php                           // Object cache + transient fallback wrappers
│   │   └── Stopwatch.php                       // Micro-timing instrumentation
│   │
│   ├── Privacy/                                // Core privacy hooks (GDPR/CCPA)
│   │   ├── Exporter.php
│   │   └── Eraser.php
│   │
│   ├── Utilities/                              // Cross-cutting helpers
│   │   ├── Sanitize.php
│   │   ├── Escaper.php
│   │   ├── Logger.php                          // Structured logs w/ PII redaction
│   │   ├── Hooks.php                           // Public actions/filters registry
│   │   └── Helpers.php                         // Money, dates, arrays, retries
│   │
│   └── Exceptions/                             // Domain-specific exceptions
│       ├── ValidationException.php
│       ├── WebhookException.php
│       └── PayoutException.php
│
├── assets/                                     // Built/static assets (kept minimal for perf)
│   ├── admin/                                  // Admin-only JS/CSS bundles
│   │   ├── js/
│   │   │   ├── dashboard.js
│   │   │   └── settings.js
│   │   └── css/
│   │       ├── dashboard.css
│   │       └── settings.css
│   ├── public/                                 // Public-facing JS/CSS bundles
│   │   ├── js/
│   │   │   └── frontend.js
│   │   └── css/
│   │       └── frontend.css
│   └── svg/                                    // Shared icon sprite(s)
│       └── icons.svg
│
├── views/                                      // Server-rendered view templates (escaped, i18n)
│   ├── admin/
│   │   ├── dashboard.php
│   │   ├── settings.php
│   │   ├── tools.php
│   │   └── partials/
│   │       ├── card-metric.php
│   │       └── table-activity.php
│   └── public/
│       └── limit-status.php
│
├── docs/                                       // Human docs for devs/ops (non-runtime)
│   ├── API.md
│   ├── INTEGRATIONS.md
│   ├── SECURITY.md
│   ├── MIGRATIONS.md
│   ├── CONTRIBUTING.md
│   └── CHANGELOG.md
│
├── tests/                                      // Complete automated test suites (TDD-first)
│   ├── bootstrap.php                           // Loads WP test suite + migrations + fixtures
│   ├── Unit/
│   │   ├── RoleManagerTest.php
│   │   ├── LimitManagerTest.php
│   │   ├── EncryptionManagerTest.php
│   │   ├── ValidationManagerTest.php
│   │   ├── PlaidWebhookValidatorTest.php
│   │   └── OfferCalculatorTest.php
│   ├── Integration/
│   │   ├── DatabaseMigrationTest.php
│   │   ├── TransactionsRepositoryTest.php
│   │   ├── WSFormPaymentListenerTest.php
│   │   └── PayoutManagerIntegrationTest.php
│   ├── E2E/
│   │   ├── playwright.config.ts
│   │   └── specs/
│   │       ├── limits-smoke.spec.ts
│   │       └── dashboard-live-metrics.spec.ts
│   └── fixtures/
│       ├── users.csv
│       └── transactions.csv
│
├── bin/                                        // Tooling scripts (non-runtime)
│   └── install-wp-tests.sh
│
└── .github/                                    // CI/CD & security workflows
    └── workflows/
        ├── ci.yml                              // Lint → Static analysis → Tests → Build → Make-pot → Artifacts
        └── codeql.yml                          // CodeQL security scan
---

### **PRD Requirement → File(s) Mapping (exact traceability)**

**Federal limits (24h/7d/MTD/YTD), preflight & UI**

-   Calc & policy: src/Domain/Services/LimitManager.php
-   REST preflight: src/REST/Controllers/LimitsController.php, src/REST/Schemas/limits-response.json, src/REST/Routes.php, src/REST/Permissions.php
-   Public widget/shortcode: src/Public/Shortcodes/LimitStatusShortcode.php, src/Public/Assets/limit-widget.js, src/Public/Assets/limit-widget.css, views/public/limit-status.php
-   Admin widget & dashboard: src/Admin/Widgets/FederalLimitWidget.php, src/Admin/Screens/Dashboard.php, assets/admin/js/dashboard.js, assets/admin/css/dashboard.css
**Progressive roles (“Subscriber + one progressive role”) with expirations (30m/45m/15m)**

-   Role orchestration: src/Domain/Services/RoleManager.php
-   Cleanup/expiry jobs: src/Jobs/CleanupExpiredRolesJob.php, src/Jobs/Schedules.php
-   Settings/visibility: src/Admin/Screens/Settings.php
**Secret Validation SC1–SC5**

-   Validators: src/Security/ValidationManager.php
-   Wiring at edges: Controllers/listeners call SCx in:
    -   src/Integration/Plaid/LinkHandler.php (SC1/SC2)
    -   src/REST/Controllers/LimitsController.php (SC preflight as needed)
    -   src/Integration/WSForm/PaymentSuccessListener.php (SC3)
    -   src/Domain/Services/PayoutManager.php (SC4/SC5)
**Digital DNA (invisible), session store & fallbacks**

-   DNA generation/correlation: src/Security/DigitalDNA/DNAService.php
-   Session storage: src/Security/DigitalDNA/SessionStore.php
-   Fallback table: src/Database/Migrations/2025\_01\_01\_000006\_create\_sessions\_fallback.php
**Plaid OAuth 2.0 link, exchange, identity, RTP/FedNow capability**

-   OAuth/link/exchange: src/Integration/Plaid/OAuth.php, src/Integration/Plaid/LinkHandler.php
-   HTTP client & endpoints (identity/capabilities/transfers): src/Integration/Plaid/Client.php
**Plaid webhooks: ES256 JWT, SHA-256 body hash, ≤5-minute age, replay guard**

-   Intake controller: src/Integration/Plaid/WebhookController.php
-   Replay protection: src/Security/WebhookReplayGuard.php
-   Rate limiting: src/Security/RateLimiter.php
**Authorize.Net via WS Form (no Accept.js / no PAN)**

-   Success-only bridge: src/Integration/WSForm/PaymentSuccessListener.php
-   WS Form meta extractors: src/Integration/WSForm/Extractors.php
-   Presence/fallback guard: src/Integration/WSForm/Compatibility.php
-   (Optional) ANet webhook signature (if used for reconciliation): src/Integration/AuthorizeNet/WebhookValidator.php
**Payouts via RTP/FedNow; retries, reconciliation**

-   Payout orchestration: src/Domain/Services/PayoutManager.php (implements PayoutProviderInterface via Plaid Client)
-   Data stores: src/Database/Repositories/PayoutsRepository.php
-   Retry job: src/Jobs/RetryPayoutJob.php, scheduling in src/Jobs/Schedules.php
**Transactions & audit trail**

-   Repository layer: src/Database/Repositories/TransactionsRepository.php, src/Database/Repositories/UserActivityRepository.php, src/Database/Repositories/SystemEventsRepository.php
-   Entities: src/Domain/Entities/Transaction.php, src/Domain/Entities/UserSession.php
-   Admin list table: src/Admin/ListTables/Transactions\_List\_Table.php, view partials in views/admin/partials/\*
**Database schema, dbDelta migrations, legacy upgrade path, versioning**

-   Table SQL & names: src/Database/Schema/dbDeltaSql.php, src/Database/Schema/Tables.php
-   Migrations: src/Database/Migrations/\*
-   Versioned upgrader & legacy copy: src/Database/Upgrader.php
-   Activation wiring: src/Core/Providers/DatabaseServiceProvider.php
**Security: AES-256-CBC encryption & rotation, nonces, prepared SQL, sanitization/escaping**

-   Encryption & rotation: src/Security/EncryptionManager.php
-   Nonces: src/Security/Nonce.php
-   Sanitization/escaping: src/Utilities/Sanitize.php, src/Utilities/Escaper.php
-   Prepared SQL enforced in all repositories under src/Database/Repositories/\*
**REST API contracts with JSON Schemas + permission\_callback**

-   Route registry: src/REST/Routes.php
-   Permissions: src/REST/Permissions.php
-   Controllers: src/REST/Controllers/\*
-   Schemas: src/REST/Schemas/\*.json
**Admin Dashboard (real-time metrics w/ 30s cache)**

-   Screen + assets: src/Admin/Screens/Dashboard.php, assets/admin/js/dashboard.js, assets/admin/css/dashboard.css
-   REST endpoint: src/REST/Controllers/MetricsController.php
-   Cache helper: src/Performance/Cache.php
**Privacy: exporter/eraser**

-   Exporter/Eraser: src/Privacy/Exporter.php, src/Privacy/Eraser.php
**Uninstall policy & data retention (multisite-aware)**

-   Cleanup: uninstall.php (reads policy constant/option)
-   Docs & migration policy: docs/MIGRATIONS.md, docs/SECURITY.md
**Testing & CI (TDD-first)**

-   Unit tests: tests/Unit/\* (roles, limits, encryption, validators, offers)
-   Integration tests: tests/Integration/\* (migrations, repositories, WS Form listener, payout manager)
-   E2E smoke: tests/E2E/specs/\* (limits widget, dashboard live metrics)
-   Test bootstrap/fixtures: tests/bootstrap.php, tests/fixtures/\*, bin/install-wp-tests.sh
-   CI workflow: .github/workflows/ci.yml (lint→static→tests→build→make-pot), security scan: .github/workflows/codeql.yml
**i18n for PHP & JS**

-   Loaders: src/Core/Providers/I18nServiceProvider.php
-   Catalogs: languages/\*.pot, languages/\*-js.json
**Operator/Dev tooling**

-   WP-CLI commands: src/CLI/\*
-   Feature flags: src/Config/features.php
-   Hooks/extension points: src/Utilities/Hooks.php
-   Developer docs: docs/\*.md
**Performance**

-   Cache utilities & timing: src/Performance/Cache.php, src/Performance/Stopwatch.php
-   Light assets structure under assets/ only
**Observability / Structured logging**

-   Logger abstraction: src/Utilities/Logger.php (PII redaction)
-   Storage: src/Database/Repositories/SystemEventsRepository.php
-   Admin surfacing: views/admin/partials/table-activity.php, src/Admin/Screens/Dashboard.php

This mapping directly reflects the PRD’s functional and non-functional requirements and the customer-journey Mermaid diagram, ensuring each requirement has an exact implementation home and corresponding tests.
```
