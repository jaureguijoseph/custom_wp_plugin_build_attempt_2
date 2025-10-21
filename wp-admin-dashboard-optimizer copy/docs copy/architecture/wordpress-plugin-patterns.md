# WordPress Plugin Coordination Patterns
## Modal Integration and Workflow Orchestration

### Executive Summary

This document defines WordPress-specific patterns for coordinating between external service modals while maintaining clean plugin architecture. These patterns focus on event-driven communication, status management, and extensible design within WordPress conventions.

## 1. WordPress Hook-Based Modal Coordination

### 1.1 Modal Event Hook System

```php
<?php
namespace WPAdminOptimizer\Patterns;

/**
 * Modal coordination using WordPress action/filter hook system
 * Provides loose coupling between modal handlers and business logic
 */
class ModalHookCoordinator {
    public function __construct() {
        $this->registerModalHooks();
    }
    
    /**
     * Register all modal-related hooks
     */
    private function registerModalHooks(): void {
        // Modal initiation hooks
        add_action('wpado_initiate_plaid_flow', [$this, 'handlePlaidInitiation'], 10, 2);
        add_action('wpado_initiate_payment_flow', [$this, 'handlePaymentInitiation'], 10, 3);
        
        // Modal response hooks
        add_action('wpado_plaid_success', [$this, 'handlePlaidSuccess'], 10, 3);
        add_action('wpado_plaid_error', [$this, 'handlePlaidError'], 10, 3);
        add_action('wpado_payment_success', [$this, 'handlePaymentSuccess'], 10, 3);
        add_action('wpado_payment_error', [$this, 'handlePaymentError'], 10, 3);
        
        // Status transition hooks
        add_action('wpado_status_transition', [$this, 'logStatusTransition'], 10, 4);
        
        // Filter hooks for customization
        add_filter('wpado_plaid_config', [$this, 'filterPlaidConfig'], 10, 2);
        add_filter('wpado_payment_config', [$this, 'filterPaymentConfig'], 10, 2);
        add_filter('wpado_error_messages', [$this, 'customizeErrorMessages'], 10, 2);
    }
    
    /**
     * Handle Plaid modal initiation
     * 
     * @param int $userId User ID
     * @param array $context Additional context data
     */
    public function handlePlaidInitiation(int $userId, array $context): void {
        // Apply filters to allow customization
        $plaidConfig = apply_filters('wpado_plaid_config', [
            'environment' => 'sandbox',
            'products' => ['auth', 'identity'],
            'country_codes' => ['US']
        ], $userId);
        
        // Log the initiation
        do_action('wpado_log_event', 'plaid_modal_initiated', $userId, $context);
        
        // Allow other plugins to hook into this event
        do_action('wpado_before_plaid_modal', $userId, $plaidConfig);
        
        // Generate link token and prepare modal
        $linkToken = $this->generatePlaidLinkToken($userId, $plaidConfig);
        
        // Store workflow state
        $this->updateWorkflowState($userId, 'plaid_initiated', [
            'link_token' => $linkToken,
            'initiated_at' => current_time('mysql'),
            'context' => $context
        ]);
        
        do_action('wpado_after_plaid_modal_setup', $userId, $linkToken);
    }
    
    /**
     * Handle successful Plaid modal completion
     * 
     * @param int $userId User ID
     * @param array $plaidData Data returned from Plaid
     * @param array $metadata Additional metadata
     */
    public function handlePlaidSuccess(int $userId, array $plaidData, array $metadata): void {
        // Validate the response
        if (!$this->validatePlaidResponse($plaidData)) {
            do_action('wpado_plaid_error', $userId, ['error' => 'invalid_response'], $metadata);
            return;
        }
        
        // Allow preprocessing of Plaid data
        $plaidData = apply_filters('wpado_process_plaid_data', $plaidData, $userId, $metadata);
        
        // Perform identity verification
        $identityCheck = $this->performIdentityVerification($userId, $plaidData);
        
        if (!$identityCheck->isVerified()) {
            do_action('wpado_identity_verification_failed', $userId, $identityCheck->getErrors());
            return;
        }
        
        // Check RTP capability
        $rtpCheck = $this->checkRTPCapability($plaidData);
        
        if (!$rtpCheck->isCompatible()) {
            do_action('wpado_bank_incompatible', $userId, $rtpCheck->getReason());
            return;
        }
        
        // Update user status
        do_action('wpado_status_transition', $userId, 'subscriber', 'transaction_user', 'plaid_success');
        
        // Store account information securely
        $this->storeAccountInformation($userId, $plaidData);
        
        // Log success
        do_action('wpado_log_event', 'plaid_success', $userId, $plaidData);
        
        // Proceed to next step
        do_action('wpado_initiate_payment_flow', $userId, $plaidData, $metadata);
    }
}
```

### 1.2 WordPress AJAX Pattern for Modal Communication

```php
<?php
namespace WPAdminOptimizer\AJAX;

/**
 * AJAX handlers for modal communication
 * Follows WordPress AJAX conventions with nonce verification
 */
class ModalAjaxHandler {
    public function __construct() {
        $this->registerAjaxHandlers();
    }
    
    private function registerAjaxHandlers(): void {
        // Logged-in user handlers
        add_action('wp_ajax_wpado_plaid_callback', [$this, 'handlePlaidCallback']);
        add_action('wp_ajax_wpado_authorize_callback', [$this, 'handleAuthorizeCallback']);
        add_action('wp_ajax_wpado_get_workflow_status', [$this, 'getWorkflowStatus']);
        add_action('wp_ajax_wpado_retry_operation', [$this, 'retryOperation']);
        
        // Public handlers (if needed for webhooks)
        add_action('wp_ajax_nopriv_wpado_webhook', [$this, 'handleWebhook']);
    }
    
    /**
     * Handle Plaid modal callback
     * Called when Plaid modal completes (success or error)
     */
    public function handlePlaidCallback(): void {
        // Verify nonce for security
        if (!wp_verify_nonce($_POST['_wpnonce'] ?? '', 'wpado_plaid_callback')) {
            wp_send_json_error(['message' => 'Security check failed']);
            return;
        }
        
        // Verify user is logged in
        if (!is_user_logged_in()) {
            wp_send_json_error(['message' => 'Authentication required']);
            return;
        }
        
        $userId = get_current_user_id();
        
        // Sanitize input data
        $callbackData = [
            'success' => isset($_POST['success']) && $_POST['success'] === 'true',
            'public_token' => sanitize_text_field($_POST['public_token'] ?? ''),
            'metadata' => $this->sanitizeMetadata($_POST['metadata'] ?? []),
            'error' => $this->sanitizeError($_POST['error'] ?? null)
        ];
        
        try {
            if ($callbackData['success']) {
                // Trigger success hook
                do_action('wpado_plaid_success', $userId, $callbackData, $_POST);
                
                wp_send_json_success([
                    'message' => 'Bank account linked successfully',
                    'next_step' => 'payment_modal'
                ]);
            } else {
                // Trigger error hook
                do_action('wpado_plaid_error', $userId, $callbackData['error'], $_POST);
                
                wp_send_json_error([
                    'message' => 'Bank linking failed',
                    'error' => $callbackData['error'],
                    'retry_available' => $this->canRetryPlaidOperation($userId)
                ]);
            }
        } catch (Exception $e) {
            error_log("Plaid callback error: " . $e->getMessage());
            
            wp_send_json_error([
                'message' => 'An unexpected error occurred',
                'error_code' => 'internal_error'
            ]);
        }
    }
    
    /**
     * Handle Authorize.Net modal callback
     */
    public function handleAuthorizeCallback(): void {
        // Similar structure to Plaid callback
        if (!wp_verify_nonce($_POST['_wpnonce'] ?? '', 'wpado_authorize_callback')) {
            wp_send_json_error(['message' => 'Security check failed']);
            return;
        }
        
        if (!is_user_logged_in()) {
            wp_send_json_error(['message' => 'Authentication required']);
            return;
        }
        
        $userId = get_current_user_id();
        
        $paymentData = [
            'success' => isset($_POST['success']) && $_POST['success'] === 'true',
            'payment_nonce' => sanitize_text_field($_POST['payment_nonce'] ?? ''),
            'transaction_id' => sanitize_text_field($_POST['transaction_id'] ?? ''),
            'amount' => floatval($_POST['amount'] ?? 0),
            'error' => $this->sanitizeError($_POST['error'] ?? null)
        ];
        
        try {
            if ($paymentData['success']) {
                do_action('wpado_payment_success', $userId, $paymentData, $_POST);
                
                wp_send_json_success([
                    'message' => 'Payment processed successfully',
                    'next_step' => 'payout_processing'
                ]);
            } else {
                do_action('wpado_payment_error', $userId, $paymentData['error'], $_POST);
                
                wp_send_json_error([
                    'message' => 'Payment processing failed',
                    'error' => $paymentData['error'],
                    'retry_available' => $this->canRetryPaymentOperation($userId)
                ]);
            }
        } catch (Exception $e) {
            error_log("Payment callback error: " . $e->getMessage());
            
            wp_send_json_error([
                'message' => 'Payment processing error',
                'error_code' => 'internal_error'
            ]);
        }
    }
    
    /**
     * Get current workflow status for user
     * Used for real-time status updates
     */
    public function getWorkflowStatus(): void {
        if (!wp_verify_nonce($_POST['_wpnonce'] ?? '', 'wpado_status_check')) {
            wp_send_json_error(['message' => 'Security check failed']);
            return;
        }
        
        if (!is_user_logged_in()) {
            wp_send_json_error(['message' => 'Authentication required']);
            return;
        }
        
        $userId = get_current_user_id();
        $workflowId = sanitize_text_field($_POST['workflow_id'] ?? '');
        
        $status = $this->getCurrentWorkflowStatus($userId, $workflowId);
        
        wp_send_json_success([
            'status' => $status['current_step'],
            'progress_percentage' => $status['progress_percentage'],
            'message' => $status['status_message'],
            'estimated_completion' => $status['estimated_completion'],
            'can_retry' => $status['can_retry'],
            'error_details' => $status['error_details'] ?? null
        ]);
    }
}
```

## 2. WordPress Custom Post Types for Workflow Management

### 2.1 Workflow State Management with Custom Post Types

```php
<?php
namespace WPAdminOptimizer\PostTypes;

/**
 * Custom Post Type for managing workflow states
 * Leverages WordPress's built-in post system for workflow management
 */
class WorkflowPostType {
    private const POST_TYPE = 'wpado_workflow';
    
    public function __construct() {
        add_action('init', [$this, 'registerPostType']);
        add_action('add_meta_boxes', [$this, 'addMetaBoxes']);
        add_action('save_post', [$this, 'saveWorkflowData']);
    }
    
    public function registerPostType(): void {
        register_post_type(self::POST_TYPE, [
            'labels' => [
                'name' => 'Workflow States',
                'singular_name' => 'Workflow State',
                'add_new' => 'Add New Workflow',
                'add_new_item' => 'Add New Workflow State',
                'edit_item' => 'Edit Workflow State',
                'new_item' => 'New Workflow State',
                'view_item' => 'View Workflow State',
                'search_items' => 'Search Workflow States',
                'not_found' => 'No workflow states found',
                'not_found_in_trash' => 'No workflow states found in trash'
            ],
            'public' => false,
            'show_ui' => current_user_can('manage_options'),
            'show_in_menu' => 'edit.php?post_type=' . self::POST_TYPE,
            'capability_type' => 'post',
            'capabilities' => [
                'edit_posts' => 'manage_options',
                'edit_others_posts' => 'manage_options',
                'publish_posts' => 'manage_options',
                'read_private_posts' => 'manage_options',
            ],
            'supports' => ['title', 'custom-fields'],
            'meta_box_cb' => false, // Disable default meta boxes
        ]);
    }
    
    /**
     * Create a workflow state post for a user
     */
    public function createWorkflowState(int $userId, array $workflowData): int {
        $workflowId = wp_generate_uuid4();
        
        $postData = [
            'post_type' => self::POST_TYPE,
            'post_title' => "Workflow {$workflowId} - User {$userId}",
            'post_status' => 'publish',
            'post_author' => $userId,
            'meta_input' => [
                'workflow_id' => $workflowId,
                'user_id' => $userId,
                'current_step' => $workflowData['step'] ?? 'initiated',
                'workflow_data' => wp_json_encode($workflowData),
                'created_timestamp' => current_time('timestamp'),
                'last_updated' => current_time('timestamp'),
                'expiry_timestamp' => current_time('timestamp') + (30 * MINUTE_IN_SECONDS),
                'status' => $workflowData['status'] ?? 'active'
            ]
        ];
        
        $postId = wp_insert_post($postData);
        
        if (is_wp_error($postId)) {
            throw new WorkflowException('Failed to create workflow state: ' . $postId->get_error_message());
        }
        
        // Hook for other plugins to react to workflow creation
        do_action('wpado_workflow_created', $postId, $userId, $workflowData);
        
        return $postId;
    }
    
    /**
     * Update workflow state
     */
    public function updateWorkflowState(int $postId, array $updates): bool {
        $currentData = get_post_meta($postId, 'workflow_data', true);
        $currentData = json_decode($currentData, true) ?: [];
        
        $mergedData = array_merge($currentData, $updates);
        
        $metaUpdates = [
            'workflow_data' => wp_json_encode($mergedData),
            'last_updated' => current_time('timestamp')
        ];
        
        if (isset($updates['step'])) {
            $metaUpdates['current_step'] = $updates['step'];
        }
        
        if (isset($updates['status'])) {
            $metaUpdates['status'] = $updates['status'];
        }
        
        foreach ($metaUpdates as $key => $value) {
            update_post_meta($postId, $key, $value);
        }
        
        $userId = get_post_meta($postId, 'user_id', true);
        do_action('wpado_workflow_updated', $postId, $userId, $updates);
        
        return true;
    }
    
    /**
     * Get workflow state by user ID
     */
    public function getActiveWorkflowByUser(int $userId): ?WP_Post {
        $workflows = get_posts([
            'post_type' => self::POST_TYPE,
            'meta_query' => [
                [
                    'key' => 'user_id',
                    'value' => $userId,
                    'compare' => '='
                ],
                [
                    'key' => 'status',
                    'value' => 'active',
                    'compare' => '='
                ]
            ],
            'orderby' => 'date',
            'order' => 'DESC',
            'numberposts' => 1
        ]);
        
        return $workflows[0] ?? null;
    }
    
    /**
     * Clean up expired workflows
     */
    public function cleanupExpiredWorkflows(): void {
        $expiredWorkflows = get_posts([
            'post_type' => self::POST_TYPE,
            'meta_query' => [
                [
                    'key' => 'expiry_timestamp',
                    'value' => current_time('timestamp'),
                    'compare' => '<',
                    'type' => 'NUMERIC'
                ],
                [
                    'key' => 'status',
                    'value' => ['active', 'processing'],
                    'compare' => 'IN'
                ]
            ],
            'numberposts' => -1
        ]);
        
        foreach ($expiredWorkflows as $workflow) {
            $userId = get_post_meta($workflow->ID, 'user_id', true);
            
            // Update status to expired
            update_post_meta($workflow->ID, 'status', 'expired');
            
            // Reset user role if needed
            $user = new WP_User($userId);
            if ($user->exists() && in_array($user->roles[0] ?? '', ['plaid_user', 'transaction_user', 'payment_user'])) {
                $user->remove_role($user->roles[0]);
                $user->add_role('subscriber');
            }
            
            do_action('wpado_workflow_expired', $workflow->ID, $userId);
        }
    }
}
```

## 3. WordPress Options API for Configuration Management

### 3.1 Modal Configuration Management

```php
<?php
namespace WPAdminOptimizer\Configuration;

/**
 * Configuration management using WordPress Options API
 * Handles modal-specific configurations and plugin settings
 */
class ModalConfigurationManager {
    private const OPTION_GROUP = 'wpado_modal_settings';
    
    private array $defaultConfigs = [
        'plaid' => [
            'environment' => 'sandbox',
            'client_name' => '',
            'products' => ['auth', 'identity'],
            'country_codes' => ['US'],
            'language' => 'en',
            'webhook_url' => '',
            'link_customization' => [
                'color' => '#000000',
                'institution_search_enabled' => true,
                'payment_initiation_enabled' => false
            ]
        ],
        'authorize_net' => [
            'environment' => 'sandbox',
            'api_login_id' => '',
            'client_key' => '',
            'signature_key' => '',
            'accept_js_url' => 'https://jstest.authorize.net/v1/Accept.js',
            'form_customization' => [
                'color_scheme' => 'default',
                'show_labels' => true,
                'placeholder_text' => true
            ]
        ],
        'workflow' => [
            'federal_limits' => [
                '24_hours' => 500.00,
                '7_days' => 1500.00,
                'month_to_date' => 3500.00,
                'year_to_date' => 8500.00
            ],
            'fee_structure' => [
                'percentage_fee' => 8.5,
                'flat_fee' => 1.00,
                'minimum_transaction' => 20.00,
                'maximum_transaction' => 500.00
            ],
            'timeout_settings' => [
                'plaid_modal_timeout' => 300, // 5 minutes
                'payment_modal_timeout' => 180, // 3 minutes
                'workflow_expiry' => 1800 // 30 minutes
            ],
            'retry_settings' => [
                'max_plaid_retries' => 3,
                'max_payment_retries' => 2,
                'retry_delay_base' => 30 // seconds
            ]
        ]
    ];
    
    public function __construct() {
        add_action('admin_init', [$this, 'registerSettings']);
        add_action('admin_menu', [$this, 'addSettingsPage']);
    }
    
    public function registerSettings(): void {
        register_setting(self::OPTION_GROUP, 'wpado_plaid_config');
        register_setting(self::OPTION_GROUP, 'wpado_authorize_config');
        register_setting(self::OPTION_GROUP, 'wpado_workflow_config');
        
        // Add settings sections
        add_settings_section(
            'plaid_settings',
            'Plaid Modal Configuration',
            [$this, 'plaidSectionCallback'],
            self::OPTION_GROUP
        );
        
        add_settings_section(
            'authorize_settings',
            'Authorize.Net Modal Configuration',
            [$this, 'authorizeSectionCallback'],
            self::OPTION_GROUP
        );
        
        add_settings_section(
            'workflow_settings',
            'Workflow Configuration',
            [$this, 'workflowSectionCallback'],
            self::OPTION_GROUP
        );
        
        // Add individual settings fields
        $this->addSettingsFields();
    }
    
    /**
     * Get configuration for a specific modal
     */
    public function getModalConfig(string $modalType, string $environment = null): array {
        $optionName = "wpado_{$modalType}_config";
        $storedConfig = get_option($optionName, []);
        $defaultConfig = $this->defaultConfigs[$modalType] ?? [];
        
        $config = wp_parse_args($storedConfig, $defaultConfig);
        
        // Override environment if specified
        if ($environment) {
            $config['environment'] = $environment;
        }
        
        // Apply filters for customization
        return apply_filters("wpado_{$modalType}_config", $config, $environment);
    }
    
    /**
     * Update modal configuration
     */
    public function updateModalConfig(string $modalType, array $config): bool {
        $optionName = "wpado_{$modalType}_config";
        $currentConfig = get_option($optionName, []);
        
        $mergedConfig = array_merge($currentConfig, $config);
        
        // Validate configuration before saving
        $validationResult = $this->validateConfig($modalType, $mergedConfig);
        
        if (!$validationResult->isValid()) {
            throw new ConfigurationException(
                'Invalid configuration: ' . implode(', ', $validationResult->getErrors())
            );
        }
        
        $updated = update_option($optionName, $mergedConfig);
        
        if ($updated) {
            do_action('wpado_config_updated', $modalType, $mergedConfig);
        }
        
        return $updated;
    }
    
    /**
     * Get Plaid Link configuration for frontend
     */
    public function getPlaidLinkConfig(int $userId): array {
        $baseConfig = $this->getModalConfig('plaid');
        
        $linkConfig = [
            'env' => $baseConfig['environment'],
            'clientName' => $baseConfig['client_name'] ?: get_option('blogname'),
            'product' => $baseConfig['products'],
            'countryCodes' => $baseConfig['country_codes'],
            'language' => $baseConfig['language'],
            'user' => [
                'client_user_id' => (string) $userId
            ]
        ];
        
        // Add customization options
        if (!empty($baseConfig['link_customization'])) {
            $linkConfig['customization'] = $baseConfig['link_customization'];
        }
        
        return apply_filters('wpado_plaid_link_config', $linkConfig, $userId);
    }
    
    /**
     * Get Authorize.Net Accept.js configuration
     */
    public function getAuthorizeNetConfig(): array {
        $baseConfig = $this->getModalConfig('authorize_net');
        
        $acceptConfig = [
            'apiLoginID' => $baseConfig['api_login_id'],
            'clientKey' => $baseConfig['client_key'],
            'acceptUIFormBtnTxt' => 'Submit Payment',
            'acceptUIFormHeaderTxt' => 'Gift Card Payment',
            'paymentOptions' => [
                'showCreditCard' => true,
                'showDebitCard' => true,
                'showGiftCard' => true
            ]
        ];
        
        // Add customization
        if (!empty($baseConfig['form_customization'])) {
            $acceptConfig = array_merge($acceptConfig, $baseConfig['form_customization']);
        }
        
        return apply_filters('wpado_authorize_net_config', $acceptConfig);
    }
    
    /**
     * Environment-specific configuration switching
     */
    public function switchEnvironment(string $environment): void {
        $validEnvironments = ['sandbox', 'production'];
        
        if (!in_array($environment, $validEnvironments)) {
            throw new InvalidArgumentException('Invalid environment specified');
        }
        
        // Update Plaid environment
        $plaidConfig = $this->getModalConfig('plaid');
        $plaidConfig['environment'] = $environment;
        $this->updateModalConfig('plaid', $plaidConfig);
        
        // Update Authorize.Net environment
        $authorizeConfig = $this->getModalConfig('authorize_net');
        $authorizeConfig['environment'] = $environment;
        $this->updateModalConfig('authorize_net', $authorizeConfig);
        
        do_action('wpado_environment_switched', $environment);
    }
}
```

## 4. WordPress Cron for Background Processing

### 4.1 Background Task Management

```php
<?php
namespace WPAdminOptimizer\Background;

/**
 * WordPress Cron integration for background processing
 * Handles retry logic, cleanup tasks, and scheduled operations
 */
class BackgroundTaskManager {
    public function __construct() {
        $this->registerCronHooks();
        $this->scheduleRecurringTasks();
    }
    
    private function registerCronHooks(): void {
        // Retry operations
        add_action('wpado_retry_plaid_operation', [$this, 'retryPlaidOperation']);
        add_action('wpado_retry_payment_operation', [$this, 'retryPaymentOperation']);
        add_action('wpado_retry_payout_operation', [$this, 'retryPayoutOperation']);
        
        // Cleanup tasks
        add_action('wpado_cleanup_expired_workflows', [$this, 'cleanupExpiredWorkflows']);
        add_action('wpado_cleanup_old_logs', [$this, 'cleanupOldLogs']);
        add_action('wpado_reset_daily_limits', [$this, 'resetDailyLimits']);
        
        // Status monitoring
        add_action('wpado_check_pending_payouts', [$this, 'checkPendingPayouts']);
        add_action('wpado_sync_account_balances', [$this, 'syncAccountBalances']);
        
        // Maintenance tasks
        add_action('wpado_database_maintenance', [$this, 'performDatabaseMaintenance']);
        add_action('wpado_generate_reports', [$this, 'generateDailyReports']);
    }
    
    private function scheduleRecurringTasks(): void {
        // Schedule cleanup tasks
        if (!wp_next_scheduled('wpado_cleanup_expired_workflows')) {
            wp_schedule_event(time(), 'hourly', 'wpado_cleanup_expired_workflows');
        }
        
        if (!wp_next_scheduled('wpado_cleanup_old_logs')) {
            wp_schedule_event(time(), 'daily', 'wpado_cleanup_old_logs');
        }
        
        // Schedule limit reset (daily at midnight)
        if (!wp_next_scheduled('wpado_reset_daily_limits')) {
            $midnight = strtotime('tomorrow midnight');
            wp_schedule_event($midnight, 'daily', 'wpado_reset_daily_limits');
        }
        
        // Schedule payout monitoring (every 5 minutes)
        if (!wp_next_scheduled('wpado_check_pending_payouts')) {
            wp_schedule_event(time(), 'five_minutes', 'wpado_check_pending_payouts');
        }
    }
    
    /**
     * Retry failed Plaid operation
     */
    public function retryPlaidOperation(int $userId, array $context = []): void {
        $workflow = $this->getActiveWorkflow($userId);
        
        if (!$workflow) {
            error_log("No active workflow found for user {$userId}");
            return;
        }
        
        $retryCount = get_post_meta($workflow->ID, 'plaid_retry_count', true) ?: 0;
        $maxRetries = apply_filters('wpado_max_plaid_retries', 3);
        
        if ($retryCount >= $maxRetries) {
            // Max retries reached, mark workflow as failed
            update_post_meta($workflow->ID, 'status', 'failed');
            update_post_meta($workflow->ID, 'failure_reason', 'max_plaid_retries_exceeded');
            
            do_action('wpado_workflow_failed', $workflow->ID, $userId, 'max_plaid_retries');
            return;
        }
        
        // Increment retry count
        update_post_meta($workflow->ID, 'plaid_retry_count', $retryCount + 1);
        
        // Attempt to reinitiate Plaid flow
        try {
            do_action('wpado_initiate_plaid_flow', $userId, array_merge($context, [
                'retry_attempt' => $retryCount + 1
            ]));
            
            // Log retry attempt
            do_action('wpado_log_event', 'plaid_retry_attempted', $userId, [
                'retry_count' => $retryCount + 1,
                'workflow_id' => get_post_meta($workflow->ID, 'workflow_id', true)
            ]);
            
        } catch (Exception $e) {
            // Schedule next retry with exponential backoff
            $delay = min(300 * (2 ** $retryCount), 3600); // Max 1 hour delay
            wp_schedule_single_event(time() + $delay, 'wpado_retry_plaid_operation', [$userId, $context]);
            
            error_log("Plaid retry failed for user {$userId}: " . $e->getMessage());
        }
    }
    
    /**
     * Check pending payouts and update status
     */
    public function checkPendingPayouts(): void {
        global $wpdb;
        
        $pendingPayouts = $wpdb->get_results("
            SELECT p.ID, p.meta_value as workflow_data
            FROM {$wpdb->posts} p
            INNER JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id
            WHERE p.post_type = 'wpado_workflow'
            AND pm.meta_key = 'status'
            AND pm.meta_value = 'payout_pending'
            AND p.post_date > DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        
        foreach ($pendingPayouts as $payout) {
            $workflowData = get_post_meta($payout->ID, 'workflow_data', true);
            $workflowData = json_decode($workflowData, true);
            
            $userId = get_post_meta($payout->ID, 'user_id', true);
            
            try {
                $payoutStatus = $this->checkPayoutStatus($workflowData['payout_id'] ?? '');
                
                if ($payoutStatus->isCompleted()) {
                    // Update workflow status
                    update_post_meta($payout->ID, 'status', 'completed');
                    
                    // Update user role back to subscriber
                    $user = new WP_User($userId);
                    if ($user->exists()) {
                        $user->remove_role('payment_user');
                        $user->add_role('subscriber');
                    }
                    
                    // Send completion notification
                    do_action('wpado_payout_completed', $userId, $payoutStatus->getData());
                    
                } elseif ($payoutStatus->isFailed()) {
                    // Mark as failed and alert admin
                    update_post_meta($payout->ID, 'status', 'failed');
                    update_post_meta($payout->ID, 'failure_reason', $payoutStatus->getError());
                    
                    do_action('wpado_payout_failed', $userId, $payoutStatus->getError());
                }
                
            } catch (Exception $e) {
                error_log("Error checking payout status: " . $e->getMessage());
            }
        }
    }
    
    /**
     * Cleanup expired workflows
     */
    public function cleanupExpiredWorkflows(): void {
        $workflowPostType = new \WPAdminOptimizer\PostTypes\WorkflowPostType();
        $workflowPostType->cleanupExpiredWorkflows();
        
        do_action('wpado_expired_workflows_cleaned');
    }
    
    /**
     * Custom cron schedule for 5-minute intervals
     */
    public static function addCustomCronSchedules(array $schedules): array {
        $schedules['five_minutes'] = [
            'interval' => 300,
            'display' => 'Every 5 Minutes'
        ];
        
        return $schedules;
    }
}

// Register custom cron schedule
add_filter('cron_schedules', [\WPAdminOptimizer\Background\BackgroundTaskManager::class, 'addCustomCronSchedules']);
```

These WordPress-specific patterns provide a robust foundation for modal coordination while leveraging WordPress's built-in systems for configuration management, background processing, and workflow state management. The patterns emphasize WordPress conventions while maintaining clean separation between modal handling and business logic.