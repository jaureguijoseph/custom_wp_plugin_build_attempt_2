# User Journey - Modal Workflow Architecture
## Corrected Gift Card Liquidation Process

### Executive Summary

This document outlines the corrected user journey through our modal-based gift card liquidation system. The workflow emphasizes modal coordination, status tracking, and error recovery while eliminating direct payment data handling to avoid PCI compliance requirements.

## 1. Complete User Journey Flow

### 1.1 Workflow Overview Diagram

```mermaid
flowchart TD
    A[User Dashboard] --> B[Click "Sell Gift Card" Button]
    
    B --> C[WS Form Hidden Fields Submission]
    C --> |"Captures: Name, DOB, Email, Invoice#, IP"| D[Federal Limit Check]
    
    D --> E{Limits Check}
    E -->|Exceeded| F[Display Limit Error + Next Available Time]
    E -->|Within Limits| G[Launch Plaid Link Modal]
    
    F --> A
    
    G --> H[Plaid Modal: Bank Selection & Authentication]
    H --> I{Plaid Modal Result}
    
    I -->|Success| J[Store Account Info + Identity Check]
    I -->|Error/Cancel| K[Handle Plaid Error]
    I -->|Exit| L[User Cancelled - Reset Status]
    
    K --> M{Error Type}
    M -->|Temporary| N[Show Retry Option]
    M -->|Bank Not Supported| O[Show Bank Compatibility Error]
    M -->|Authentication Failed| P[Show Auth Error + Retry]
    
    N --> G
    O --> A
    P --> G
    L --> A
    
    J --> Q[RTP/FedNow Capability Check]
    Q --> R{Bank Compatible?}
    
    R -->|No| S[Display Bank Incompatibility Error]
    R -->|Yes| T[Identity Verification Check]
    
    S --> A
    
    T --> U{Identity Verified?}
    U -->|Failed| V[Display Identity Verification Error]
    U -->|Success| W[Update Role: Subscriber → Transaction User]
    
    V --> A
    
    W --> X[Launch Authorize.Net Accept.js Modal]
    X --> Y[Authorize.Net Modal: Gift Card Processing]
    Y --> Z{Payment Result}
    
    Z -->|Success| AA[Store Transaction Details]
    Z -->|Declined| BB[Handle Payment Declined]
    Z -->|Error| CC[Handle Payment Error]
    Z -->|Cancel| DD[User Cancelled Payment]
    
    BB --> EE{Retry Allowed?}
    EE -->|Yes| FF[Show Retry Option]
    EE -->|No| GG[Show Final Error]
    
    FF --> X
    GG --> A
    CC --> X
    DD --> A
    
    AA --> HH[Update Role: Transaction User → Payment User]
    HH --> II[Calculate Net Payout Amount]
    II --> JJ[Initiate RTP/FedNow Payout via Plaid]
    JJ --> KK{Payout Result}
    
    KK -->|Success| LL[Transaction Complete Notification]
    KK -->|Failed| MM[Payout Error Handling]
    
    LL --> NN[Update Role: Payment User → Subscriber]
    NN --> OO[Display Success Dashboard]
    
    MM --> PP[Log Payout Error + Admin Alert]
    PP --> QQ[User Notification: Processing Delay]
    QQ --> A
    
    OO --> A
```

### 1.2 Step-by-Step User Experience

#### Phase 1: Initial Setup (User Dashboard)
**User Action**: User logs into WordPress dashboard and sees "Sell My Gift Card" button
**System Response**: Button renders as WS Form with hidden fields pre-populated

```php
// Hidden form fields automatically populated
$hiddenFields = [
    'wp_user_id' => get_current_user_id(),
    'first_name' => get_user_meta($userId, 'first_name', true),
    'last_name' => get_user_meta($userId, 'last_name', true),
    'date_of_birth' => get_user_meta($userId, 'date_of_birth', true),
    'email' => get_userdata($userId)->user_email,
    'user_ip' => $_SERVER['REMOTE_ADDR'],
    'invoice_number' => wp_generate_password(12, false),
    'session_token' => wp_create_nonce('gift_card_session_' . $userId)
];
```

#### Phase 2: Federal Limit Validation
**User Action**: Clicks "Sell Gift Card" button
**System Process**: Server-side federal limit check

```php
class FederalLimitChecker {
    public function checkUserLimits(int $userId): LimitCheckResult {
        $limits = [
            '24_hours' => 500.00,
            '7_days' => 1500.00,
            'month_to_date' => 3500.00,
            'year_to_date' => 8500.00
        ];
        
        $usage = $this->calculateUsage($userId);
        
        foreach ($limits as $period => $limit) {
            if ($usage[$period] >= $limit) {
                return LimitCheckResult::exceeded($period, $limit, $usage[$period]);
            }
        }
        
        return LimitCheckResult::withinLimits();
    }
    
    private function calculateUsage(int $userId): array {
        // Query transaction database for user's historical usage
        global $wpdb;
        
        $last24Hours = $wpdb->get_var($wpdb->prepare("
            SELECT SUM(gross_amount) 
            FROM {$wpdb->prefix}transaction_coordination 
            WHERE user_id = %d 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ", $userId)) ?: 0;
        
        // Similar calculations for 7 days, month-to-date, year-to-date
        return [
            '24_hours' => floatval($last24Hours),
            '7_days' => $this->calculate7DayUsage($userId),
            'month_to_date' => $this->calculateMonthUsage($userId),
            'year_to_date' => $this->calculateYearUsage($userId)
        ];
    }
}
```

**User Feedback**: 
- ✅ **Within Limits**: Proceed to Plaid modal
- ❌ **Limits Exceeded**: Display clear error message with next available amount and time

#### Phase 3: Bank Account Linking (Plaid Modal)
**User Action**: Modal launches with Plaid Link interface
**Modal Process**: Plaid handles all bank authentication and account selection

```javascript
// Frontend Plaid Link integration
class PlaidLinkHandler {
    constructor(linkToken, userId) {
        this.linkToken = linkToken;
        this.userId = userId;
        this.handler = null;
    }
    
    initializePlaid() {
        this.handler = Plaid.create({
            token: this.linkToken,
            onSuccess: (public_token, metadata) => {
                this.handlePlaidSuccess(public_token, metadata);
            },
            onExit: (err, metadata) => {
                this.handlePlaidExit(err, metadata);
            },
            onEvent: (eventName, metadata) => {
                this.logPlaidEvent(eventName, metadata);
            }
        });
    }
    
    handlePlaidSuccess(public_token, metadata) {
        // Send to WordPress for processing
        jQuery.post(ajaxurl, {
            action: 'handle_plaid_success',
            public_token: public_token,
            metadata: metadata,
            user_id: this.userId,
            _wpnonce: wpado_nonce
        }).done((response) => {
            if (response.success) {
                this.proceedToPaymentModal(response.data);
            } else {
                this.handlePlaidError(response.data);
            }
        });
    }
    
    handlePlaidExit(err, metadata) {
        if (err != null) {
            this.logError('plaid_error', err);
            this.showUserError('Bank linking failed. Please try again.');
        } else {
            this.logEvent('plaid_user_exit', metadata);
            this.resetUserWorkflow();
        }
    }
}
```

**Modal Success Path**:
1. User selects bank and authenticates
2. Plaid returns account information
3. System performs identity verification
4. System checks RTP/FedNow compatibility
5. ✅ Success → Proceed to payment modal

**Modal Error Paths**:
- Bank not supported → Show error, allow different bank selection
- Authentication failed → Show retry option
- RTP/FedNow not supported → Show bank compatibility error
- User exits modal → Reset workflow, return to dashboard

#### Phase 4: Identity and Compatibility Verification
**System Process**: Validate bank account and user identity

```php
class BankCompatibilityChecker {
    public function checkRTPCapability(array $accountData): CompatibilityResult {
        $bankRoutingNumber = $accountData['routing_number'];
        
        // Check against known RTP-compatible banks
        $rtpBanks = $this->getRTPCompatibleBanks();
        
        if (!in_array($bankRoutingNumber, $rtpBanks)) {
            return CompatibilityResult::incompatible(
                'RTP_NOT_SUPPORTED',
                'Your bank does not currently support instant payments. Please try a different bank account.'
            );
        }
        
        return CompatibilityResult::compatible();
    }
    
    public function verifyUserIdentity(int $userId, array $plaidIdentityData): VerificationResult {
        $userProfile = get_userdata($userId);
        $storedDOB = get_user_meta($userId, 'date_of_birth', true);
        
        // Compare Plaid identity data with stored user information
        $identityMatches = [
            'name_match' => $this->compareNames(
                $userProfile->first_name . ' ' . $userProfile->last_name,
                $plaidIdentityData['names'][0] ?? ''
            ),
            'dob_match' => $this->compareDates($storedDOB, $plaidIdentityData['dob'] ?? ''),
            'address_match' => $this->compareAddresses(
                get_user_meta($userId, 'billing_address', true),
                $plaidIdentityData['addresses'][0] ?? []
            )
        ];
        
        $matchScore = array_sum($identityMatches) / count($identityMatches);
        
        if ($matchScore < 0.8) { // 80% match threshold
            return VerificationResult::failed('Identity verification failed');
        }
        
        return VerificationResult::verified($matchScore);
    }
}
```

#### Phase 5: Gift Card Payment Processing (Authorize.Net Modal)
**System Action**: Launch Authorize.Net Accept.js modal for gift card processing
**User Action**: Enter gift card details in secure modal

```javascript
// Authorize.Net Accept.js integration
class AuthorizeNetHandler {
    constructor(userId, transactionAmount) {
        this.userId = userId;
        this.amount = transactionAmount;
    }
    
    initializePaymentModal() {
        const authData = {
            apiLoginID: wpado_config.authorize_net.login_id,
            clientKey: wpado_config.authorize_net.client_key
        };
        
        Accept.dispatchData(authData, this.handlePaymentResponse.bind(this));
    }
    
    handlePaymentResponse(response) {
        if (response.messages.resultCode === "Ok") {
            // Payment token received successfully
            this.processPayment(response.opaqueData);
        } else {
            // Handle payment error
            this.handlePaymentError(response.messages.message);
        }
    }
    
    processPayment(opaqueData) {
        jQuery.post(ajaxurl, {
            action: 'process_gift_card_payment',
            payment_nonce: opaqueData.dataValue,
            amount: this.amount,
            user_id: this.userId,
            _wpnonce: wpado_nonce
        }).done((response) => {
            if (response.success) {
                this.proceedToPayout(response.data);
            } else {
                this.handleServerError(response.data);
            }
        });
    }
}
```

**Payment Success Path**:
1. User enters gift card details
2. Authorize.Net validates and processes payment
3. System receives payment confirmation
4. Transaction details logged to database
5. User role updated to "payment_user"
6. ✅ Proceed to payout initiation

**Payment Error Paths**:
- Payment declined → Show user-friendly error, allow retry
- Invalid gift card → Show validation error, allow correction
- Technical error → Show generic error, allow retry
- User cancels → Return to dashboard

#### Phase 6: Payout Processing
**System Process**: Calculate net payout and initiate transfer

```php
class PayoutProcessor {
    public function calculateNetPayout(float $giftCardAmount): PayoutCalculation {
        $feePercentage = get_option('wpado_fee_percentage', 8.5); // 8.5% default
        $flatFee = get_option('wpado_flat_fee', 1.00); // $1.00 default
        
        $percentageFee = ($giftCardAmount * $feePercentage) / 100;
        $totalFees = $percentageFee + $flatFee;
        $netPayout = $giftCardAmount - $totalFees;
        
        return new PayoutCalculation([
            'gross_amount' => $giftCardAmount,
            'percentage_fee' => $percentageFee,
            'flat_fee' => $flatFee,
            'total_fees' => $totalFees,
            'net_payout' => $netPayout
        ]);
    }
    
    public function initiatePlaidPayout(int $userId, PayoutCalculation $payout): PayoutResult {
        $plaidAccessToken = $this->getEncryptedUserToken($userId);
        $accountId = get_user_meta($userId, 'plaid_primary_account_id', true);
        
        try {
            $transferRequest = [
                'access_token' => $plaidAccessToken,
                'account_id' => $accountId,
                'type' => 'credit',
                'network' => 'rtp', // Real-time payments
                'amount' => [
                    'value' => $payout->getNetPayout(),
                    'currency' => 'USD'
                ],
                'description' => 'Gift card liquidation payout'
            ];
            
            $plaidResponse = $this->plaidClient->createTransfer($transferRequest);
            
            return PayoutResult::success($plaidResponse);
            
        } catch (PlaidException $e) {
            return PayoutResult::failed($e->getMessage(), $e->getCode());
        }
    }
}
```

**Payout Success Path**:
1. Calculate net payout amount (gross - fees)
2. Initiate RTP/FedNow transfer via Plaid
3. Monitor transfer status
4. ✅ Success → Complete transaction, notify user
5. Reset user role to "subscriber"

**Payout Error Paths**:
- Bank account issues → Log error, notify admin, inform user
- Transfer limits exceeded → Schedule for later processing
- Technical failure → Retry mechanism with exponential backoff

## 2. Error Recovery and User Communication

### 2.1 Error Message Templates

```php
class UserMessageManager {
    private const MESSAGE_TEMPLATES = [
        'federal_limits_exceeded' => [
            'title' => 'Daily Limit Reached',
            'message' => 'You have reached your federal transaction limit. You can liquidate ${remaining_amount} more on {next_reset_date}.',
            'type' => 'warning',
            'actions' => ['view_limits', 'return_dashboard']
        ],
        
        'bank_not_supported' => [
            'title' => 'Bank Not Compatible',
            'message' => 'Unfortunately, your selected bank does not support instant payments. Please try linking a different bank account.',
            'type' => 'error',
            'actions' => ['try_different_bank', 'return_dashboard']
        ],
        
        'identity_verification_failed' => [
            'title' => 'Identity Verification Required',
            'message' => 'We need to verify your identity to proceed. Please ensure your account information matches your bank records.',
            'type' => 'warning',
            'actions' => ['retry_verification', 'contact_support']
        ],
        
        'payment_declined' => [
            'title' => 'Gift Card Payment Declined',
            'message' => 'Your gift card payment was declined. Please check your card details and try again.',
            'type' => 'error',
            'actions' => ['retry_payment', 'return_dashboard']
        ]
    ];
    
    public function displayUserMessage(string $messageType, array $variables = []): void {
        $template = self::MESSAGE_TEMPLATES[$messageType] ?? null;
        
        if (!$template) {
            return;
        }
        
        $message = $this->interpolateVariables($template['message'], $variables);
        
        $this->renderUserNotification([
            'title' => $template['title'],
            'message' => $message,
            'type' => $template['type'],
            'actions' => $template['actions']
        ]);
    }
}
```

### 2.2 Retry Logic and Timing

```php
class RetryManager {
    private const RETRY_LIMITS = [
        'plaid_linking' => 3,
        'payment_processing' => 2,
        'payout_processing' => 5
    ];
    
    private const RETRY_DELAYS = [
        'plaid_linking' => [0, 30, 300], // Immediate, 30s, 5min
        'payment_processing' => [0, 60], // Immediate, 1min
        'payout_processing' => [300, 600, 1200, 3600, 7200] // 5min, 10min, 20min, 1hr, 2hr
    ];
    
    public function canRetry(int $userId, string $operation): bool {
        $retryCount = get_user_meta($userId, "retry_count_{$operation}", true) ?: 0;
        $maxRetries = self::RETRY_LIMITS[$operation] ?? 0;
        
        return $retryCount < $maxRetries;
    }
    
    public function scheduleRetry(int $userId, string $operation): int {
        $retryCount = get_user_meta($userId, "retry_count_{$operation}", true) ?: 0;
        $delays = self::RETRY_DELAYS[$operation] ?? [0];
        $delay = $delays[$retryCount] ?? end($delays);
        
        // Increment retry count
        update_user_meta($userId, "retry_count_{$operation}", $retryCount + 1);
        
        // Schedule the retry
        wp_schedule_single_event(
            time() + $delay,
            "wpado_retry_{$operation}",
            [$userId]
        );
        
        return $delay;
    }
}
```

## 3. Status Tracking and Monitoring

### 3.1 Real-Time Status Updates

```javascript
// Frontend status monitoring
class WorkflowStatusMonitor {
    constructor(userId, workflowId) {
        this.userId = userId;
        this.workflowId = workflowId;
        this.statusPollingInterval = 2000; // 2 seconds
        this.maxPollingDuration = 300000; // 5 minutes
        this.pollingTimer = null;
    }
    
    startStatusMonitoring() {
        this.pollingTimer = setInterval(() => {
            this.checkWorkflowStatus();
        }, this.statusPollingInterval);
        
        // Stop polling after max duration
        setTimeout(() => {
            this.stopStatusMonitoring();
        }, this.maxPollingDuration);
    }
    
    checkWorkflowStatus() {
        jQuery.post(ajaxurl, {
            action: 'get_workflow_status',
            user_id: this.userId,
            workflow_id: this.workflowId,
            _wpnonce: wpado_nonce
        }).done((response) => {
            if (response.success) {
                this.updateStatusDisplay(response.data);
                
                if (response.data.status === 'completed' || response.data.status === 'failed') {
                    this.stopStatusMonitoring();
                }
            }
        });
    }
    
    updateStatusDisplay(statusData) {
        const statusElement = jQuery('#workflow-status');
        const progressBar = jQuery('#progress-bar');
        
        statusElement.text(statusData.message);
        progressBar.css('width', statusData.progress_percentage + '%');
        
        if (statusData.status === 'completed') {
            this.showCompletionMessage(statusData);
        } else if (statusData.status === 'failed') {
            this.showErrorMessage(statusData);
        }
    }
}
```

### 3.2 Admin Monitoring Dashboard

```php
class AdminMonitoringDashboard {
    public function displayWorkflowMetrics(): void {
        $metrics = $this->calculateWorkflowMetrics();
        
        echo '<div class="wpado-metrics-dashboard">';
        echo '<div class="metric-card">';
        echo '<h3>Success Rate</h3>';
        echo '<div class="metric-value">' . round($metrics['success_rate'], 2) . '%</div>';
        echo '</div>';
        
        echo '<div class="metric-card">';
        echo '<h3>Average Processing Time</h3>';
        echo '<div class="metric-value">' . $this->formatDuration($metrics['avg_processing_time']) . '</div>';
        echo '</div>';
        
        echo '<div class="metric-card">';
        echo '<h3>Active Workflows</h3>';
        echo '<div class="metric-value">' . $metrics['active_workflows'] . '</div>';
        echo '</div>';
        echo '</div>';
        
        $this->displayRecentErrors();
        $this->displayWorkflowQueue();
    }
    
    private function calculateWorkflowMetrics(): array {
        global $wpdb;
        
        // Calculate success rate over last 24 hours
        $totalWorkflows = $wpdb->get_var("
            SELECT COUNT(*) 
            FROM {$wpdb->prefix}transaction_coordination 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        
        $successfulWorkflows = $wpdb->get_var("
            SELECT COUNT(*) 
            FROM {$wpdb->prefix}transaction_coordination 
            WHERE coordination_status = 'payout_completed' 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        
        $successRate = $totalWorkflows > 0 ? ($successfulWorkflows / $totalWorkflows) * 100 : 0;
        
        return [
            'success_rate' => $successRate,
            'avg_processing_time' => $this->calculateAverageProcessingTime(),
            'active_workflows' => $this->getActiveWorkflowCount(),
            'total_workflows_24h' => $totalWorkflows,
            'successful_workflows_24h' => $successfulWorkflows
        ];
    }
}
```

This comprehensive user journey documentation provides a clear understanding of the modal-based workflow, error handling strategies, and monitoring capabilities that ensure a smooth user experience while maintaining system reliability and extensibility.