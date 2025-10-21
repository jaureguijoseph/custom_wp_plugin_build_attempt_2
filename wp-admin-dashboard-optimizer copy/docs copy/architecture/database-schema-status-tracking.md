# Database Schema for Modal Status Tracking
## WordPress Plugin Database Design

### Executive Summary

This document defines the database schema for tracking modal integration workflows, user status transitions, and transaction coordination. The design focuses on **status tracking without storing sensitive payment data**, leveraging WordPress's existing user system while adding specialized tables for workflow management.

## 1. Database Design Principles

### 1.1 Core Design Philosophy
- **Status Tracking Focus**: Store workflow states and status transitions, not sensitive data
- **WordPress Integration**: Leverage existing WordPress tables and conventions
- **Audit Trail**: Complete logging of all status changes and events
- **Performance Optimized**: Proper indexing for real-time status queries
- **Extensible**: Schema designed for future modal integrations

### 1.2 Data Classification
```
┌─────────────────┬──────────────────┬─────────────────┬───────────────────┐
│ Classification  │ Example Data     │ Storage Method  │ Encryption        │
├─────────────────┼──────────────────┼─────────────────┼───────────────────┤
│ Public          │ Workflow steps   │ Plain text      │ Not required      │
│ Internal        │ Status messages  │ Plain text      │ Not required      │
│ Confidential    │ User identifiers │ Hashed/Encoded  │ Optional          │
│ Restricted      │ Modal tokens     │ Database only   │ Required          │
└─────────────────┴──────────────────┴─────────────────┴───────────────────┘
```

## 2. Core Database Tables

### 2.1 Modal Workflow States Table

```sql
-- Primary workflow state tracking
CREATE TABLE wp_modal_workflow_states (
    id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    workflow_id VARCHAR(255) NOT NULL UNIQUE,
    user_id BIGINT(20) UNSIGNED NOT NULL,
    workflow_type ENUM('gift_card_liquidation', 'bank_verification', 'payment_processing') DEFAULT 'gift_card_liquidation',
    current_step ENUM(
        'initiated', 
        'federal_limits_checked', 
        'plaid_modal_launched', 
        'bank_linked', 
        'identity_verified', 
        'payment_modal_launched', 
        'payment_authorized', 
        'payout_processing', 
        'completed', 
        'failed', 
        'expired', 
        'cancelled'
    ) DEFAULT 'initiated',
    
    -- Progress tracking
    step_sequence JSON, -- Array of completed steps
    progress_percentage DECIMAL(5,2) DEFAULT 0.00,
    
    -- Timing information
    initiated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    
    -- Status metadata
    workflow_data JSON, -- Non-sensitive workflow context
    error_details JSON, -- Error information if failed
    retry_count INT DEFAULT 0,
    
    -- Indexing for performance
    INDEX idx_workflow_id (workflow_id),
    INDEX idx_user_id (user_id),
    INDEX idx_current_step (current_step),
    INDEX idx_workflow_type (workflow_type),
    INDEX idx_initiated_at (initiated_at),
    INDEX idx_expires_at (expires_at),
    INDEX idx_last_activity (last_activity),
    
    -- Foreign key constraints
    FOREIGN KEY (user_id) REFERENCES wp_users(ID) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

### 2.2 Modal Event Log Table

```sql
-- Detailed event logging for all modal interactions
CREATE TABLE wp_modal_event_log (
    id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    workflow_id VARCHAR(255) NOT NULL,
    user_id BIGINT(20) UNSIGNED NOT NULL,
    
    -- Event details
    event_type ENUM(
        'workflow_initiated',
        'plaid_modal_opened',
        'plaid_modal_success',
        'plaid_modal_error',
        'plaid_modal_exit',
        'authorize_modal_opened',
        'authorize_modal_success',
        'authorize_modal_error',
        'authorize_modal_exit',
        'status_transition',
        'federal_limit_check',
        'identity_verification',
        'payout_initiated',
        'payout_completed',
        'error_occurred',
        'retry_attempted'
    ) NOT NULL,
    
    event_subtype VARCHAR(50), -- Additional event classification
    event_message TEXT, -- Human-readable event description
    event_data JSON, -- Structured event data (non-sensitive)
    
    -- Context information
    user_role_before VARCHAR(50),
    user_role_after VARCHAR(50),
    modal_session_id VARCHAR(255), -- For correlating modal events
    
    -- Technical details
    user_ip VARCHAR(45),
    user_agent TEXT,
    request_source ENUM('frontend_ajax', 'webhook', 'cron_job', 'admin_action') DEFAULT 'frontend_ajax',
    
    -- Status and timing
    event_status ENUM('success', 'warning', 'error', 'info') DEFAULT 'info',
    processing_time_ms INT UNSIGNED, -- Event processing time
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Indexing for queries and reporting
    INDEX idx_workflow_id (workflow_id),
    INDEX idx_user_id (user_id),
    INDEX idx_event_type (event_type),
    INDEX idx_event_status (event_status),
    INDEX idx_created_at (created_at),
    INDEX idx_modal_session (modal_session_id),
    INDEX idx_composite_workflow_event (workflow_id, event_type, created_at),
    
    -- Foreign key constraints
    FOREIGN KEY (user_id) REFERENCES wp_users(ID) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

### 2.3 Transaction Coordination Table

```sql
-- High-level transaction coordination (no sensitive payment data)
CREATE TABLE wp_transaction_coordination (
    id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    workflow_id VARCHAR(255) NOT NULL,
    user_id BIGINT(20) UNSIGNED NOT NULL,
    
    -- Transaction identification
    transaction_reference VARCHAR(255) NOT NULL UNIQUE, -- Internal reference
    invoice_number VARCHAR(255) NOT NULL,
    
    -- Amount information (business logic only)
    gift_card_amount DECIMAL(10,2) NOT NULL,
    fee_percentage DECIMAL(5,2) NOT NULL,
    flat_fee DECIMAL(10,2) NOT NULL,
    net_payout_amount DECIMAL(10,2) NOT NULL,
    
    -- Processing status
    coordination_status ENUM(
        'initiated',
        'limits_verified',
        'bank_linked',
        'identity_verified',
        'payment_authorized',
        'payout_processing',
        'payout_completed',
        'reconciled',
        'failed',
        'cancelled'
    ) DEFAULT 'initiated',
    
    -- External service references (non-sensitive identifiers only)
    plaid_item_id VARCHAR(255), -- Plaid item identifier
    authorize_transaction_ref VARCHAR(255), -- Authorize.Net transaction reference
    payout_reference_id VARCHAR(255), -- Payout system reference
    
    -- Reconciliation tracking
    reconciliation_status ENUM('pending', 'matched', 'mismatch', 'manual_review') DEFAULT 'pending',
    reconciliation_notes TEXT,
    reconciled_at TIMESTAMP NULL,
    
    -- Timing information
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    
    -- Error handling
    error_code VARCHAR(50),
    error_message TEXT,
    error_data JSON,
    
    -- Indexing
    INDEX idx_workflow_id (workflow_id),
    INDEX idx_user_id (user_id),
    INDEX idx_transaction_ref (transaction_reference),
    INDEX idx_invoice_number (invoice_number),
    INDEX idx_coordination_status (coordination_status),
    INDEX idx_reconciliation_status (reconciliation_status),
    INDEX idx_created_at (created_at),
    INDEX idx_completed_at (completed_at),
    
    -- Foreign key constraints
    FOREIGN KEY (user_id) REFERENCES wp_users(ID) ON DELETE CASCADE,
    FOREIGN KEY (workflow_id) REFERENCES wp_modal_workflow_states(workflow_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

### 2.4 Federal Limits Tracking Table

```sql
-- Federal limit tracking and enforcement
CREATE TABLE wp_federal_limits_tracking (
    id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT(20) UNSIGNED NOT NULL,
    
    -- Limit periods
    limit_period ENUM('24_hours', '7_days', 'month_to_date', 'year_to_date') NOT NULL,
    period_start_date DATE NOT NULL,
    period_end_date DATE NOT NULL,
    
    -- Limit amounts
    limit_amount DECIMAL(10,2) NOT NULL,
    used_amount DECIMAL(10,2) DEFAULT 0.00,
    remaining_amount DECIMAL(10,2) NOT NULL,
    
    -- Usage tracking
    transaction_count INT DEFAULT 0,
    last_transaction_date TIMESTAMP NULL,
    
    -- Reset tracking
    last_reset_date TIMESTAMP,
    next_reset_date TIMESTAMP,
    auto_reset_enabled BOOLEAN DEFAULT TRUE,
    
    -- Status
    status ENUM('active', 'exceeded', 'suspended', 'reset_pending') DEFAULT 'active',
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Unique constraint per user per period
    UNIQUE KEY unique_user_period (user_id, limit_period),
    
    -- Indexing
    INDEX idx_user_id (user_id),
    INDEX idx_limit_period (limit_period),
    INDEX idx_status (status),
    INDEX idx_next_reset_date (next_reset_date),
    INDEX idx_period_dates (period_start_date, period_end_date),
    
    -- Foreign key constraint
    FOREIGN KEY (user_id) REFERENCES wp_users(ID) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

### 2.5 User Modal Sessions Table

```sql
-- Track modal sessions and temporary tokens
CREATE TABLE wp_user_modal_sessions (
    id BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL UNIQUE,
    user_id BIGINT(20) UNSIGNED NOT NULL,
    workflow_id VARCHAR(255) NOT NULL,
    
    -- Modal type and status
    modal_type ENUM('plaid_link', 'authorize_net', 'custom_modal') NOT NULL,
    session_status ENUM('initiated', 'active', 'completed', 'expired', 'error') DEFAULT 'initiated',
    
    -- Session data (temporary, non-sensitive)
    session_data JSON, -- Modal configuration and state
    temporary_tokens JSON, -- Encrypted temporary tokens (auto-expire)
    
    -- Timing and expiry
    initiated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP NULL,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Security tracking
    user_ip VARCHAR(45),
    user_agent_hash VARCHAR(64), -- Hashed for privacy
    browser_fingerprint VARCHAR(255), -- For session validation
    
    -- Cleanup automation
    auto_cleanup BOOLEAN DEFAULT TRUE,
    cleanup_after_expiry BOOLEAN DEFAULT TRUE,
    
    -- Indexing
    INDEX idx_session_id (session_id),
    INDEX idx_user_id (user_id),
    INDEX idx_workflow_id (workflow_id),
    INDEX idx_modal_type (modal_type),
    INDEX idx_session_status (session_status),
    INDEX idx_expires_at (expires_at),
    INDEX idx_last_activity (last_activity),
    
    -- Foreign key constraints
    FOREIGN KEY (user_id) REFERENCES wp_users(ID) ON DELETE CASCADE,
    FOREIGN KEY (workflow_id) REFERENCES wp_modal_workflow_states(workflow_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

## 3. WordPress Integration Tables

### 3.1 Extended User Metadata

```sql
-- Extend WordPress user meta for modal-specific data
-- Uses existing wp_usermeta table with these specific meta_keys:

INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES 
-- Modal preferences
(?, 'wpado_modal_preferences', '{"plaid_environment": "production", "skip_intro": false}'),

-- Bank linking status
(?, 'wpado_bank_link_status', 'not_linked'), -- 'not_linked', 'linked', 'verified', 'expired'
(?, 'wpado_bank_link_date', '2024-01-01 00:00:00'),

-- Identity verification
(?, 'wpado_identity_status', 'not_verified'), -- 'not_verified', 'pending', 'verified', 'failed'
(?, 'wpado_identity_verified_date', NULL),

-- Transaction history summary
(?, 'wpado_total_transactions', '0'),
(?, 'wpado_total_liquidated', '0.00'),
(?, 'wpado_last_transaction_date', NULL),

-- Preferences and settings
(?, 'wpado_notification_preferences', '{"email": true, "sms": false}'),
(?, 'wpado_dashboard_layout', 'default');
```

### 3.2 Custom User Roles Implementation

```php
<?php
// WordPress roles are stored in wp_options as 'wp_user_roles'
// Custom roles for modal workflow:

$custom_roles = [
    'plaid_user' => [
        'name' => 'Plaid User',
        'capabilities' => [
            'read' => true,
            'wpado_link_bank' => true,
            'wpado_view_status' => true
        ]
    ],
    'transaction_user' => [
        'name' => 'Transaction User', 
        'capabilities' => [
            'read' => true,
            'wpado_link_bank' => true,
            'wpado_view_status' => true,
            'wpado_process_payment' => true,
            'wpado_view_limits' => true
        ]
    ],
    'payment_user' => [
        'name' => 'Payment User',
        'capabilities' => [
            'read' => true,
            'wpado_link_bank' => true,
            'wpado_view_status' => true,
            'wpado_process_payment' => true,
            'wpado_view_limits' => true,
            'wpado_request_payout' => true,
            'wpado_view_history' => true
        ]
    ]
];

// Role transitions are logged in wp_modal_event_log table
```

## 4. Database Maintenance and Optimization

### 4.1 Automated Cleanup Procedures

```sql
-- Cleanup expired workflow states (run daily)
DELETE FROM wp_modal_workflow_states 
WHERE expires_at IS NOT NULL 
AND expires_at < DATE_SUB(NOW(), INTERVAL 1 HOUR)
AND current_step IN ('expired', 'failed', 'cancelled');

-- Cleanup old event logs (run weekly, keep 90 days)
DELETE FROM wp_modal_event_log 
WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY);

-- Cleanup expired modal sessions (run hourly)
DELETE FROM wp_user_modal_sessions 
WHERE expires_at < NOW() 
AND auto_cleanup = TRUE;

-- Reset federal limits (run daily at midnight)
UPDATE wp_federal_limits_tracking 
SET used_amount = 0.00, 
    remaining_amount = limit_amount,
    transaction_count = 0,
    last_reset_date = NOW(),
    status = 'active'
WHERE next_reset_date <= NOW() 
AND auto_reset_enabled = TRUE;
```

### 4.2 Performance Optimization Queries

```sql
-- Index optimization for common queries
-- 1. Get active workflow for user
EXPLAIN SELECT * FROM wp_modal_workflow_states 
WHERE user_id = ? 
AND current_step NOT IN ('completed', 'failed', 'expired', 'cancelled') 
ORDER BY initiated_at DESC LIMIT 1;

-- 2. Check federal limits for user
EXPLAIN SELECT * FROM wp_federal_limits_tracking 
WHERE user_id = ? 
AND status = 'active';

-- 3. Get recent events for workflow
EXPLAIN SELECT * FROM wp_modal_event_log 
WHERE workflow_id = ? 
ORDER BY created_at DESC LIMIT 20;

-- 4. Transaction coordination status
EXPLAIN SELECT * FROM wp_transaction_coordination 
WHERE user_id = ? 
AND coordination_status IN ('payout_processing', 'payout_completed') 
ORDER BY created_at DESC;
```

## 5. Data Access Patterns

### 5.1 Repository Pattern Implementation

```php
<?php
namespace WPAdminOptimizer\Database;

class WorkflowStateRepository {
    private wpdb $wpdb;
    
    public function __construct() {
        global $wpdb;
        $this->wpdb = $wpdb;
    }
    
    /**
     * Get active workflow for user
     */
    public function getActiveWorkflow(int $userId): ?array {
        $query = $this->wpdb->prepare("
            SELECT * FROM {$this->wpdb->prefix}modal_workflow_states 
            WHERE user_id = %d 
            AND current_step NOT IN ('completed', 'failed', 'expired', 'cancelled')
            ORDER BY initiated_at DESC 
            LIMIT 1
        ", $userId);
        
        $result = $this->wpdb->get_row($query, ARRAY_A);
        
        if ($result && $result['workflow_data']) {
            $result['workflow_data'] = json_decode($result['workflow_data'], true);
        }
        
        return $result;
    }
    
    /**
     * Update workflow step
     */
    public function updateWorkflowStep(string $workflowId, string $newStep, array $data = []): bool {
        // Get current progress
        $currentWorkflow = $this->wpdb->get_row($this->wpdb->prepare("
            SELECT step_sequence, progress_percentage 
            FROM {$this->wpdb->prefix}modal_workflow_states 
            WHERE workflow_id = %s
        ", $workflowId), ARRAY_A);
        
        if (!$currentWorkflow) {
            return false;
        }
        
        // Update step sequence
        $stepSequence = json_decode($currentWorkflow['step_sequence'] ?: '[]', true);
        $stepSequence[] = [
            'step' => $newStep,
            'timestamp' => current_time('mysql'),
            'data' => $data
        ];
        
        // Calculate progress
        $progressMap = [
            'initiated' => 0,
            'federal_limits_checked' => 15,
            'plaid_modal_launched' => 25,
            'bank_linked' => 40,
            'identity_verified' => 55,
            'payment_modal_launched' => 65,
            'payment_authorized' => 80,
            'payout_processing' => 90,
            'completed' => 100
        ];
        
        $newProgress = $progressMap[$newStep] ?? $currentWorkflow['progress_percentage'];
        
        // Update database
        $updated = $this->wpdb->update(
            $this->wpdb->prefix . 'modal_workflow_states',
            [
                'current_step' => $newStep,
                'step_sequence' => wp_json_encode($stepSequence),
                'progress_percentage' => $newProgress,
                'last_activity' => current_time('mysql')
            ],
            ['workflow_id' => $workflowId],
            ['%s', '%s', '%f', '%s'],
            ['%s']
        );
        
        return $updated !== false;
    }
    
    /**
     * Log workflow event
     */
    public function logEvent(array $eventData): int {
        $result = $this->wpdb->insert(
            $this->wpdb->prefix . 'modal_event_log',
            [
                'workflow_id' => $eventData['workflow_id'],
                'user_id' => $eventData['user_id'],
                'event_type' => $eventData['event_type'],
                'event_subtype' => $eventData['event_subtype'] ?? null,
                'event_message' => $eventData['message'] ?? '',
                'event_data' => wp_json_encode($eventData['data'] ?? []),
                'event_status' => $eventData['status'] ?? 'info',
                'user_ip' => $_SERVER['REMOTE_ADDR'] ?? '',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                'processing_time_ms' => $eventData['processing_time'] ?? null
            ],
            [
                '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d'
            ]
        );
        
        return $result ? $this->wpdb->insert_id : 0;
    }
}
```

## 6. Backup and Recovery Strategy

### 6.1 Backup Requirements

```sql
-- Critical data backup (daily)
-- 1. Active workflows
CREATE TABLE wp_modal_workflow_states_backup AS 
SELECT * FROM wp_modal_workflow_states 
WHERE current_step NOT IN ('completed', 'failed', 'expired');

-- 2. Federal limits (daily)
CREATE TABLE wp_federal_limits_tracking_backup AS 
SELECT * FROM wp_federal_limits_tracking;

-- 3. Recent transaction coordination (weekly)
CREATE TABLE wp_transaction_coordination_backup AS 
SELECT * FROM wp_transaction_coordination 
WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY);
```

### 6.2 Recovery Procedures

```php
<?php
class DatabaseRecoveryManager {
    public function validateDataIntegrity(): array {
        $issues = [];
        
        // Check for orphaned workflow states
        $orphanedWorkflows = $this->wpdb->get_var("
            SELECT COUNT(*) FROM {$this->wpdb->prefix}modal_workflow_states ws
            LEFT JOIN {$this->wpdb->users} u ON ws.user_id = u.ID
            WHERE u.ID IS NULL
        ");
        
        if ($orphanedWorkflows > 0) {
            $issues[] = "Found {$orphanedWorkflows} orphaned workflow states";
        }
        
        // Check for inconsistent federal limits
        $inconsistentLimits = $this->wpdb->get_var("
            SELECT COUNT(*) FROM {$this->wpdb->prefix}federal_limits_tracking
            WHERE used_amount > limit_amount
        ");
        
        if ($inconsistentLimits > 0) {
            $issues[] = "Found {$inconsistentLimits} inconsistent federal limit records";
        }
        
        return $issues;
    }
    
    public function repairDataIntegrity(): bool {
        // Clean up orphaned records
        $this->wpdb->query("
            DELETE ws FROM {$this->wpdb->prefix}modal_workflow_states ws
            LEFT JOIN {$this->wpdb->users} u ON ws.user_id = u.ID
            WHERE u.ID IS NULL
        ");
        
        // Fix federal limit inconsistencies
        $this->wpdb->query("
            UPDATE {$this->wpdb->prefix}federal_limits_tracking
            SET remaining_amount = GREATEST(0, limit_amount - used_amount)
            WHERE remaining_amount != (limit_amount - used_amount)
        ");
        
        return true;
    }
}
```

This comprehensive database schema provides a robust foundation for tracking modal workflow states while maintaining WordPress integration standards and ensuring optimal performance for real-time status tracking operations.