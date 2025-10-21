# OAuth 2.0 Native WordPress Implementation for Plaid API

## Overview

This document provides a comprehensive guide for implementing OAuth 2.0 authentication with Plaid API in WordPress using **only native WordPress functionality** - NO external plugins like WPGETAPI Pro.

## Architecture Overview

```
WordPress User → Custom REST API → Plaid Link → Token Exchange → Secure Storage
```

## 1. Plugin Structure

```
plaid-integration/
├── plaid-integration.php          # Main plugin file
├── includes/
│   ├── class-oauth-handler.php    # OAuth flow management
│   ├── class-token-manager.php    # Token storage/retrieval
│   ├── class-plaid-client.php     # Plaid API client
│   ├── class-security.php         # Security utilities
│   └── class-database.php         # Custom table management
├── assets/
│   ├── js/
│   │   └── plaid-link.js          # Frontend Plaid Link
│   └── css/
│       └── admin-styles.css       # Admin styling
└── templates/
    ├── oauth-callback.php         # OAuth callback template
    └── link-account.php           # Account linking interface
```

## 2. Core Implementation

### Main Plugin File (plaid-integration.php)

```php
<?php
/**
 * Plugin Name: Plaid Integration
 * Description: Native WordPress Plaid API integration with OAuth 2.0
 * Version: 1.0.0
 * Author: Your Name
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('PLAID_PLUGIN_URL', plugin_dir_url(__FILE__));
define('PLAID_PLUGIN_PATH', plugin_dir_path(__FILE__));
define('PLAID_PLUGIN_VERSION', '1.0.0');

// Include required files
require_once PLAID_PLUGIN_PATH . 'includes/class-oauth-handler.php';
require_once PLAID_PLUGIN_PATH . 'includes/class-token-manager.php';
require_once PLAID_PLUGIN_PATH . 'includes/class-plaid-client.php';
require_once PLAID_PLUGIN_PATH . 'includes/class-security.php';
require_once PLAID_PLUGIN_PATH . 'includes/class-database.php';

class Plaid_Integration {
    
    private $oauth_handler;
    private $token_manager;
    private $plaid_client;
    
    public function __construct() {
        $this->init();
    }
    
    private function init() {
        add_action('init', array($this, 'init_plugin'));
        add_action('rest_api_init', array($this, 'register_rest_routes'));
        add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
    }
    
    public function init_plugin() {
        $this->oauth_handler = new Plaid_OAuth_Handler();
        $this->token_manager = new Plaid_Token_Manager();
        $this->plaid_client = new Plaid_Client();
    }
    
    public function register_rest_routes() {
        register_rest_route('plaid/v1', '/create-link-token', array(
            'methods' => 'POST',
            'callback' => array($this->oauth_handler, 'create_link_token'),
            'permission_callback' => array($this, 'check_permissions'),
        ));
        
        register_rest_route('plaid/v1', '/exchange-public-token', array(
            'methods' => 'POST',
            'callback' => array($this->oauth_handler, 'exchange_public_token'),
            'permission_callback' => array($this, 'check_permissions'),
        ));
        
        register_rest_route('plaid/v1', '/oauth-callback', array(
            'methods' => 'GET',
            'callback' => array($this->oauth_handler, 'handle_callback'),
            'permission_callback' => '__return_true',
        ));
    }
    
    public function check_permissions() {
        return current_user_can('read') && wp_verify_nonce($_POST['_wpnonce'], 'plaid_oauth');
    }
    
    public function enqueue_scripts() {
        if (is_user_logged_in()) {
            wp_enqueue_script(
                'plaid-link',
                'https://cdn.plaid.com/link/v2/stable/link-initialize.js',
                array(),
                null,
                true
            );
            
            wp_enqueue_script(
                'plaid-integration',
                PLAID_PLUGIN_URL . 'assets/js/plaid-link.js',
                array('jquery', 'plaid-link'),
                PLAID_PLUGIN_VERSION,
                true
            );
            
            wp_localize_script('plaid-integration', 'plaid_ajax', array(
                'ajaxurl' => rest_url('plaid/v1/'),
                'nonce' => wp_create_nonce('plaid_oauth'),
                'user_id' => get_current_user_id(),
            ));
        }
    }
    
    public function activate() {
        Plaid_Database::create_tables();
        flush_rewrite_rules();
    }
    
    public function deactivate() {
        flush_rewrite_rules();
    }
}

// Initialize plugin
new Plaid_Integration();
```

### OAuth Handler (includes/class-oauth-handler.php)

```php
<?php
class Plaid_OAuth_Handler {
    
    private $client_id;
    private $secret;
    private $environment;
    
    public function __construct() {
        $this->client_id = get_option('plaid_client_id');
        $this->secret = Plaid_Security::decrypt(get_option('plaid_secret_encrypted'));
        $this->environment = get_option('plaid_environment', 'sandbox');
    }
    
    /**
     * Create Link Token for Plaid Link
     */
    public function create_link_token($request) {
        // Verify nonce
        if (!wp_verify_nonce($request['_wpnonce'], 'plaid_oauth')) {
            return new WP_Error('invalid_nonce', 'Security check failed', array('status' => 403));
        }
        
        $user_id = get_current_user_id();
        if (!$user_id) {
            return new WP_Error('not_logged_in', 'User must be logged in', array('status' => 401));
        }
        
        $user = get_userdata($user_id);
        
        $body = array(
            'client_id' => $this->client_id,
            'secret' => $this->secret,
            'client_name' => get_bloginfo('name'),
            'country_codes' => array('US'),
            'language' => 'en',
            'user' => array(
                'client_user_id' => strval($user_id),
                'legal_name' => $user->display_name,
                'email_address' => $user->user_email,
            ),
            'products' => array('auth', 'identity', 'transactions'),
            'required_if_supported_products' => array('identity'),
            'redirect_uri' => rest_url('plaid/v1/oauth-callback'),
        );
        
        $response = $this->make_plaid_request('/link/token/create', $body);
        
        if (is_wp_error($response)) {
            return $response;
        }
        
        // Store link token temporarily
        set_transient('plaid_link_token_' . $user_id, $response['link_token'], 30 * MINUTE_IN_SECONDS);
        
        return rest_ensure_response(array(
            'link_token' => $response['link_token'],
            'expiration' => $response['expiration'],
        ));
    }
    
    /**
     * Exchange Public Token for Access Token
     */
    public function exchange_public_token($request) {
        // Verify nonce
        if (!wp_verify_nonce($request['_wpnonce'], 'plaid_oauth')) {
            return new WP_Error('invalid_nonce', 'Security check failed', array('status' => 403));
        }
        
        $user_id = get_current_user_id();
        $public_token = sanitize_text_field($request['public_token']);
        
        if (!$public_token) {
            return new WP_Error('missing_token', 'Public token is required', array('status' => 400));
        }
        
        $body = array(
            'client_id' => $this->client_id,
            'secret' => $this->secret,
            'public_token' => $public_token,
        );
        
        $response = $this->make_plaid_request('/link/token/exchange', $body);
        
        if (is_wp_error($response)) {
            return $response;
        }
        
        // Store tokens securely
        $token_manager = new Plaid_Token_Manager();
        $stored = $token_manager->store_tokens($user_id, array(
            'access_token' => $response['access_token'],
            'item_id' => $response['item_id'],
        ));
        
        if (!$stored) {
            return new WP_Error('storage_failed', 'Failed to store tokens', array('status' => 500));
        }
        
        // Update user role
        $user = new WP_User($user_id);
        $user->set_role('plaid_user');
        
        // Clean up temporary data
        delete_transient('plaid_link_token_' . $user_id);
        
        return rest_ensure_response(array(
            'success' => true,
            'message' => 'Account linked successfully',
        ));
    }
    
    /**
     * Handle OAuth Callback
     */
    public function handle_callback($request) {
        $state = sanitize_text_field($request['state']);
        $code = sanitize_text_field($request['code']);
        $error = sanitize_text_field($request['error']);
        
        if ($error) {
            return new WP_Error('oauth_error', 'OAuth error: ' . $error, array('status' => 400));
        }
        
        // Process OAuth callback
        // This would handle any additional OAuth flow steps
        
        wp_redirect(home_url('/account/?plaid=success'));
        exit;
    }
    
    /**
     * Make request to Plaid API
     */
    private function make_plaid_request($endpoint, $body) {
        $base_url = $this->get_base_url();
        
        $response = wp_remote_post($base_url . $endpoint, array(
            'headers' => array(
                'Content-Type' => 'application/json',
                'PLAID-CLIENT-ID' => $this->client_id,
                'PLAID-SECRET' => $this->secret,
            ),
            'body' => json_encode($body),
            'timeout' => 30,
        ));
        
        if (is_wp_error($response)) {
            return $response;
        }
        
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        $status_code = wp_remote_retrieve_response_code($response);
        
        if ($status_code !== 200) {
            return new WP_Error(
                'plaid_error',
                isset($data['error_message']) ? $data['error_message'] : 'Plaid API error',
                array('status' => $status_code, 'data' => $data)
            );
        }
        
        return $data;
    }
    
    private function get_base_url() {
        switch ($this->environment) {
            case 'production':
                return 'https://production.plaid.com';
            case 'development':
                return 'https://development.plaid.com';
            default:
                return 'https://sandbox.plaid.com';
        }
    }
}
```

### Token Manager (includes/class-token-manager.php)

```php
<?php
class Plaid_Token_Manager {
    
    private $table_name;
    
    public function __construct() {
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'plaid_tokens';
    }
    
    /**
     * Store tokens securely
     */
    public function store_tokens($user_id, $tokens) {
        global $wpdb;
        
        $encrypted_access_token = Plaid_Security::encrypt($tokens['access_token']);
        $token_hash = hash('sha256', $tokens['access_token']);
        
        $result = $wpdb->insert(
            $this->table_name,
            array(
                'user_id' => $user_id,
                'item_id' => $tokens['item_id'],
                'access_token_encrypted' => $encrypted_access_token,
                'token_hash' => $token_hash,
                'created_at' => current_time('mysql'),
                'updated_at' => current_time('mysql'),
            ),
            array('%d', '%s', '%s', '%s', '%s', '%s')
        );
        
        if ($result === false) {
            error_log('Failed to store Plaid tokens for user ' . $user_id);
            return false;
        }
        
        return true;
    }
    
    /**
     * Retrieve access token for user
     */
    public function get_access_token($user_id) {
        global $wpdb;
        
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT access_token_encrypted, token_hash FROM {$this->table_name} WHERE user_id = %d AND is_active = 1",
            $user_id
        ));
        
        if (!$row) {
            return false;
        }
        
        $decrypted_token = Plaid_Security::decrypt($row->access_token_encrypted);
        
        // Verify token integrity
        if (hash('sha256', $decrypted_token) !== $row->token_hash) {
            error_log('Token integrity check failed for user ' . $user_id);
            return false;
        }
        
        return $decrypted_token;
    }
    
    /**
     * Revoke tokens for user
     */
    public function revoke_tokens($user_id) {
        global $wpdb;
        
        return $wpdb->update(
            $this->table_name,
            array('is_active' => 0, 'updated_at' => current_time('mysql')),
            array('user_id' => $user_id),
            array('%d', '%s'),
            array('%d')
        );
    }
}
```

### Security Class (includes/class-security.php)

```php
<?php
class Plaid_Security {
    
    /**
     * Encrypt sensitive data
     */
    public static function encrypt($data) {
        if (!extension_loaded('openssl')) {
            throw new Exception('OpenSSL extension is required');
        }
        
        $key = self::get_encryption_key();
        $iv = openssl_random_pseudo_bytes(16);
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
        
        return base64_encode($iv . $encrypted);
    }
    
    /**
     * Decrypt sensitive data
     */
    public static function decrypt($encrypted_data) {
        if (!extension_loaded('openssl')) {
            throw new Exception('OpenSSL extension is required');
        }
        
        $key = self::get_encryption_key();
        $data = base64_decode($encrypted_data);
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        
        return openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
    }
    
    /**
     * Get encryption key
     */
    private static function get_encryption_key() {
        if (defined('PLAID_ENCRYPTION_KEY')) {
            return PLAID_ENCRYPTION_KEY;
        }
        
        // Fallback to WordPress salts (not ideal for production)
        return hash('sha256', AUTH_KEY . SECURE_AUTH_KEY);
    }
    
    /**
     * Validate user capabilities for Plaid operations
     */
    public static function can_user_access_plaid($capability = 'read') {
        return current_user_can($capability) && is_ssl();
    }
    
    /**
     * Sanitize and validate input data
     */
    public static function sanitize_plaid_input($input, $type = 'text') {
        switch ($type) {
            case 'token':
                return preg_replace('/[^a-zA-Z0-9\-_]/', '', $input);
            case 'amount':
                return floatval($input);
            default:
                return sanitize_text_field($input);
        }
    }
}
```

### Database Schema (includes/class-database.php)

```php
<?php
class Plaid_Database {
    
    public static function create_tables() {
        global $wpdb;
        
        $charset_collate = $wpdb->get_charset_collate();
        
        // Tokens table
        $tokens_table = $wpdb->prefix . 'plaid_tokens';
        $tokens_sql = "CREATE TABLE $tokens_table (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            user_id bigint(20) NOT NULL,
            item_id varchar(255) NOT NULL,
            access_token_encrypted text NOT NULL,
            token_hash varchar(64) NOT NULL,
            is_active tinyint(1) DEFAULT 1,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY user_id (user_id),
            KEY item_id (item_id)
        ) $charset_collate;";
        
        // Accounts table
        $accounts_table = $wpdb->prefix . 'plaid_accounts';
        $accounts_sql = "CREATE TABLE $accounts_table (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            user_id bigint(20) NOT NULL,
            account_id varchar(255) NOT NULL,
            item_id varchar(255) NOT NULL,
            account_type varchar(50) NOT NULL,
            account_subtype varchar(50),
            name varchar(255) NOT NULL,
            mask varchar(10),
            is_active tinyint(1) DEFAULT 1,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY unique_account (user_id, account_id),
            KEY user_id (user_id),
            KEY item_id (item_id)
        ) $charset_collate;";
        
        // Audit log table
        $audit_table = $wpdb->prefix . 'plaid_audit_log';
        $audit_sql = "CREATE TABLE $audit_table (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            user_id bigint(20),
            action varchar(100) NOT NULL,
            details text,
            ip_address varchar(45),
            user_agent text,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY user_id (user_id),
            KEY action (action),
            KEY created_at (created_at)
        ) $charset_collate;";
        
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($tokens_sql);
        dbDelta($accounts_sql);
        dbDelta($audit_sql);
    }
}
```

### Frontend JavaScript (assets/js/plaid-link.js)

```javascript
jQuery(document).ready(function($) {
    
    var linkHandler;
    
    // Initialize Plaid Link
    function initializePlaidLink() {
        // Get link token from backend
        $.ajax({
            url: plaid_ajax.ajaxurl + 'create-link-token',
            type: 'POST',
            data: {
                _wpnonce: plaid_ajax.nonce
            },
            success: function(response) {
                if (response.link_token) {
                    createPlaidLink(response.link_token);
                } else {
                    console.error('Failed to get link token');
                }
            },
            error: function(xhr) {
                console.error('Error getting link token:', xhr.responseJSON);
            }
        });
    }
    
    // Create Plaid Link handler
    function createPlaidLink(linkToken) {
        linkHandler = Plaid.create({
            token: linkToken,
            onSuccess: function(public_token, metadata) {
                // Exchange public token for access token
                $.ajax({
                    url: plaid_ajax.ajaxurl + 'exchange-public-token',
                    type: 'POST',
                    data: {
                        public_token: public_token,
                        _wpnonce: plaid_ajax.nonce
                    },
                    success: function(response) {
                        if (response.success) {
                            showSuccess('Bank account linked successfully!');
                            setTimeout(function() {
                                window.location.reload();
                            }, 2000);
                        }
                    },
                    error: function(xhr) {
                        showError('Failed to link account: ' + xhr.responseJSON.message);
                    }
                });
            },
            onExit: function(err, metadata) {
                if (err != null) {
                    console.error('Plaid Link error:', err);
                }
            },
            onEvent: function(eventName, metadata) {
                console.log('Plaid Link event:', eventName, metadata);
            }
        });
    }
    
    // Link account button click
    $(document).on('click', '.plaid-link-account', function(e) {
        e.preventDefault();
        
        if (linkHandler) {
            linkHandler.open();
        } else {
            initializePlaidLink();
        }
    });
    
    // Utility functions
    function showSuccess(message) {
        $('.plaid-messages').html('<div class="notice notice-success"><p>' + message + '</p></div>');
    }
    
    function showError(message) {
        $('.plaid-messages').html('<div class="notice notice-error"><p>' + message + '</p></div>');
    }
    
    // Initialize on page load
    if ($('.plaid-link-account').length > 0) {
        initializePlaidLink();
    }
});
```

## 3. WordPress Configuration

### wp-config.php additions:

```php
// Plaid API Configuration
define('PLAID_CLIENT_ID', 'your_client_id_here');
define('PLAID_ENCRYPTION_KEY', 'your-32-character-encryption-key');
define('PLAID_ENVIRONMENT', 'sandbox'); // or 'development' or 'production'

// Force HTTPS for OAuth
define('FORCE_SSL_ADMIN', true);
```

### Custom User Roles:

```php
// Add custom roles on plugin activation
function add_plaid_user_roles() {
    add_role('plaid_user', 'Plaid User', array(
        'read' => true,
        'plaid_link_account' => true,
    ));
    
    add_role('plaid_verified', 'Plaid Verified User', array(
        'read' => true,
        'plaid_link_account' => true,
        'plaid_make_payments' => true,
    ));
}
```

## 4. Security Best Practices

### HTTPS Enforcement:
```php
function enforce_https_for_plaid() {
    if (!is_ssl() && (is_page('account') || is_admin())) {
        wp_redirect('https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'], 301);
        exit();
    }
}
add_action('template_redirect', 'enforce_https_for_plaid');
```

### Nonce Verification:
```php
// Always verify nonces in AJAX handlers
if (!wp_verify_nonce($_POST['_wpnonce'], 'plaid_oauth')) {
    wp_die('Security check failed');
}
```

### Data Sanitization:
```php
// Sanitize all input data
$public_token = sanitize_text_field($_POST['public_token']);
$amount = floatval($_POST['amount']);
$user_id = intval($_POST['user_id']);
```

## 5. Error Handling

### Plaid API Errors:
```php
private function handle_plaid_error($error_data) {
    $error_code = $error_data['error_code'];
    
    switch ($error_code) {
        case 'INVALID_CREDENTIALS':
            return 'Invalid Plaid credentials';
        case 'INVALID_INPUT':
            return 'Invalid input provided';
        case 'RATE_LIMIT_EXCEEDED':
            return 'Too many requests, please try again later';
        default:
            return 'An error occurred connecting to your bank';
    }
}
```

### WordPress Error Logging:
```php
function log_plaid_error($message, $context = array()) {
    if (WP_DEBUG_LOG) {
        error_log('Plaid Error: ' . $message . ' Context: ' . json_encode($context));
    }
}
```

## 6. Testing

### Unit Tests:
```php
class Test_Plaid_OAuth extends WP_UnitTestCase {
    
    public function test_link_token_creation() {
        $handler = new Plaid_OAuth_Handler();
        $request = new WP_REST_Request();
        $request['_wpnonce'] = wp_create_nonce('plaid_oauth');
        
        $response = $handler->create_link_token($request);
        $this->assertNotInstanceOf('WP_Error', $response);
    }
}
```

## 7. Production Checklist

- [ ] HTTPS enforced
- [ ] Encryption keys properly set
- [ ] Database tables created
- [ ] User roles configured
- [ ] Error logging enabled
- [ ] Rate limiting implemented
- [ ] Security headers added
- [ ] CSRF protection enabled
- [ ] Input validation complete
- [ ] Audit logging active

This implementation provides a secure, native WordPress OAuth 2.0 integration with Plaid API without relying on external plugins like WPGETAPI Pro.