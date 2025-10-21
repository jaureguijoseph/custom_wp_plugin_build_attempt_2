# Automatic.css & Bricks Builder Integration Workflow

## Complete Setup & Configuration Guide

### Prerequisites Checklist
- [ ] Fresh WordPress installation
- [ ] Bricks Builder theme installed and activated
- [ ] Bricks Builder child theme created and activated
- [ ] Automatic.css plugin purchased and downloaded
- [ ] FTP/file manager access for configuration uploads

## Phase 1: Initial Installation

### Step 1: WordPress Environment Setup
```bash
# Install WordPress (latest version)
# Install Bricks Builder theme
# Activate Bricks Builder
# Create and activate child theme
```

### Step 2: Automatic.css Plugin Installation
1. Upload `automatic-css.zip` via WordPress admin
2. Activate the Automatic.css plugin
3. Verify plugin activation in dashboard

### Step 3: Download Configuration Files
From Automatic.css dashboard, download:
- `bricks-settings-blueprint.zip`
- `bricks-theme-file.zip`

Extract both files to access the JSON configuration files.

## Phase 2: Bricks Builder Configuration

### Step 4: Import Bricks Settings
1. Navigate to **Bricks > Settings**
2. Scroll to **Import/Export** section
3. Click **Choose File** and select `bricks-settings-blueprint.json`
4. Click **Import Settings**
5. Save changes

### Settings Applied Include:
```
✓ Custom breakpoints enabled
✓ Class chaining disabled  
✓ Performance optimizations
✓ Post type configurations
✓ Container settings
```

### Step 5: Import Global Theme Styles
1. Navigate to **Bricks > Theme Styles**
2. Click **Import** button
3. Select `bricks-theme-file.json`
4. Import the theme configuration
5. **Critical**: Assign theme to entire website

### Theme Styles Configuration:
```css
/* Automatically configured */
html {
  font-size: var(--root-font-size); /* 62.5% default */
}

.container {
  max-width: var(--content-width); /* 1280px default */
  margin: 0 auto;
}

/* Typography defaults */
h1, h2, h3, h4, h5, h6 {
  font-family: var(--heading-font);
  line-height: var(--heading-line-height);
}
```

## Phase 3: Core Configuration

### Step 6: Website Width Configuration
**Recommended Settings:**
- Container width: 1280px (can be adjusted to 1440px)
- Content width: Matches container width
- Mobile breakpoints: Auto-configured

### Step 7: Color System Setup
**Default Color Variables:**
```css
:root {
  /* Primary Colors */
  --primary: #2563eb;
  --primary-dark: #1e40af;
  --primary-light: #3b82f6;
  
  /* Base Colors */
  --base: #374151;
  --base-dark: #111827;
  --base-light: #6b7280;
  
  /* Action Colors */
  --action: #10b981;
  --action-dark: #059669;
  --action-light: #34d399;
  
  /* Neutral Colors */
  --white: #ffffff;
  --black: #000000;
  --gray: #9ca3af;
}
```

### Step 8: Typography Configuration
**Root Font Size Setup:**
```css
:root {
  --root-font-size: 62.5%; /* 10px base */
  
  /* Text Sizing Scale */
  --text-xs: 1.2rem; /* 12px */
  --text-s: 1.4rem;  /* 14px */
  --text-m: 1.6rem;  /* 16px */
  --text-l: 1.8rem;  /* 18px */
  --text-xl: 2.1rem; /* 21px */
  --text-xxl: 2.4rem; /* 24px */
}
```

## Phase 4: CSS Loading Optimization

### Step 9: CSS Loading Order Configuration
**Critical**: Ensure ACSS loads AFTER Bricks CSS

#### Method 1: Using Code Snippets Plugin
```php
// Add this PHP snippet
function load_acss_after_bricks() {
    if (function_exists('bricks_is_builder_main')) {
        wp_dequeue_style('automatic-css');
        wp_enqueue_style('automatic-css-late', 
            plugin_dir_url(__FILE__) . 'automatic-css/automatic.css',
            array('bricks-frontend'), 
            '1.0.0'
        );
    }
}
add_action('wp_enqueue_scripts', 'load_acss_after_bricks', 20);
```

#### Method 2: Child Theme functions.php
```php
function optimize_css_loading() {
    // Ensure ACSS loads after Bricks
    wp_enqueue_style('automatic-css', 
        get_stylesheet_directory_uri() . '/automatic-css.css',
        array('bricks-frontend'),
        '1.0.0'
    );
}
add_action('wp_enqueue_scripts', 'optimize_css_loading', 15);
```

## Phase 5: Development Workflow

### Step 10: Bricks Builder Class Integration
1. Open Bricks Builder editor
2. Select any element
3. Navigate to **Style** tab
4. Use **CSS Classes** field to add ACSS utilities

**Example Class Usage:**
```html
<!-- Grid Layout -->
<div class="grid grid-3 grid-s-1 gap-l">
  <div class="pad-m bg--base-light">Content 1</div>
  <div class="pad-m bg--base-light">Content 2</div>
  <div class="pad-m bg--base-light">Content 3</div>
</div>

<!-- Typography -->
<h2 class="text-xl text--primary weight--bold">Heading</h2>
<p class="text-m text--base line-height--loose">Body text</p>

<!-- Spacing -->
<section class="pad-section-l mar-bottom-xl">
  <div class="container pad-x-m">Content</div>
</section>
```

### Step 11: Responsive Design Implementation
**Mobile-First Approach:**
```css
/* Base (Mobile) Classes */
.grid-1        /* Single column on mobile */
.text-s        /* Smaller text on mobile */
.pad-m         /* Medium padding on mobile */

/* Small Screens (≥576px) */
.grid-s-2      /* 2 columns on small screens */
.text-s-m      /* Medium text on small screens */

/* Medium Screens (≥768px) */
.grid-m-3      /* 3 columns on medium screens */
.pad-m-l       /* Large padding on medium screens */

/* Large Screens (≥992px) */
.grid-l-4      /* 4 columns on large screens */
.text-l-xl     /* Extra large text on large screens */
```

### Step 12: Custom Variable Usage
**Extending ACSS Variables:**
```css
.custom-card {
    background: var(--base-light);
    padding: var(--space-l);
    margin-bottom: var(--space-m);
    border-radius: var(--radius-m);
    box-shadow: 0 4px 6px rgba(var(--base-dark-rgb), 0.1);
}

.custom-button {
    background: var(--action);
    color: var(--white);
    padding: var(--space-s) var(--space-m);
    border-radius: var(--radius-s);
    transition: background 0.2s ease;
}

.custom-button:hover {
    background: var(--action-dark);
}
```

## Phase 6: Advanced Configuration

### Step 13: Breakpoint Customization
**Custom Breakpoint Variables:**
```css
:root {
  --bp-xs: 320px;
  --bp-s: 576px;
  --bp-m: 768px;
  --bp-l: 992px;
  --bp-xl: 1200px;
  --bp-xxl: 1400px;
}

@media (min-width: var(--bp-m)) {
  .custom-grid-m-3 {
    grid-template-columns: repeat(3, 1fr);
  }
}
```

### Step 14: Theme Variations
**Creating Multiple Themes:**
```css
/* Light Theme (Default) */
:root {
  --bg-primary: var(--white);
  --text-primary: var(--base-dark);
}

/* Dark Theme */
[data-theme="dark"] {
  --bg-primary: var(--base-dark);
  --text-primary: var(--white);
  --base-light: #374151;
  --base-dark: #111827;
}

/* Theme Toggle Implementation */
.theme-toggle {
    background: var(--action);
    color: var(--white);
    border: none;
    padding: var(--space-s);
    border-radius: var(--radius-m);
    cursor: pointer;
}
```

## Phase 7: Testing & Optimization

### Step 15: Responsive Testing Protocol
**Device Testing Checklist:**
- [ ] Mobile phones (320px - 480px)
- [ ] Tablets (481px - 768px)
- [ ] Small laptops (769px - 1024px)
- [ ] Desktop (1025px+)
- [ ] Ultra-wide screens (1400px+)

**Testing Tools:**
- Browser DevTools responsive mode
- Real device testing
- BrowserStack/CrossBrowserTesting
- Lighthouse performance audits

### Step 16: Performance Optimization
**Performance Checklist:**
```bash
# Critical CSS inline
# Non-critical CSS deferred
# Image optimization
# Font loading optimization
# GZIP compression enabled
# Browser caching configured
```

## Phase 8: Quality Assurance

### Step 17: Code Validation
**Validation Checklist:**
- [ ] HTML validation (W3C)
- [ ] CSS validation
- [ ] Accessibility testing (WAVE, axe)
- [ ] Cross-browser compatibility
- [ ] Mobile responsiveness
- [ ] Loading speed optimization

### Step 18: Final Documentation
**Project Documentation:**
```markdown
# Project Setup Documentation

## ACSS Variables Used
- Color scheme: [Primary, Secondary, Base colors]
- Typography: [Font families, sizing scale]
- Spacing: [T-shirt sizes used]
- Breakpoints: [Custom breakpoints if any]

## Custom Classes Created
- [List of project-specific utility classes]
- [Component classes with ACSS variables]

## Performance Metrics
- Page load time: [X seconds]
- Lighthouse score: [X/100]
- Mobile usability: [Pass/Fail]
```

## Best Practices Summary

### ✅ Do's
1. **Always use child theme** for customizations
2. **Import settings only on fresh projects**
3. **Assign theme styles to entire website**
4. **Follow T-shirt sizing convention**
5. **Test responsive behavior thoroughly**
6. **Use ACSS variables for custom styles**
7. **Maintain consistent spacing/sizing**
8. **Document custom configurations**

### ❌ Don'ts
1. **Don't import settings on existing projects**
2. **Don't set conflicting global styles in Bricks**
3. **Don't override ACSS core variables randomly**
4. **Don't mix extensive custom CSS with utilities**
5. **Don't ignore mobile-first principles**
6. **Don't skip theme assignment step**
7. **Don't modify plugin files directly**

## Troubleshooting Guide

### Common Issues & Solutions

**Issue**: Classes not working
**Solution**: Check theme assignment and CSS loading order

**Issue**: Responsive not working
**Solution**: Verify breakpoint configuration and mobile-first approach

**Issue**: Colors not displaying
**Solution**: Check variable definitions and theme assignment

**Issue**: Typography inconsistent
**Solution**: Verify root font size and heading defaults

## Maintenance Workflow

### Regular Maintenance Tasks
1. **Monthly**: Check for ACSS updates
2. **Quarterly**: Performance audit
3. **Bi-annually**: Responsive testing across devices
4. **Annually**: Full accessibility audit

### Update Process
1. Backup current configuration
2. Test updates in staging environment
3. Document any breaking changes
4. Update production with verified configuration

## Conclusion

This comprehensive workflow ensures optimal integration between Automatic.css and Bricks Builder, providing a solid foundation for efficient, scalable, and maintainable WordPress development. The combination leverages the strengths of both tools while maintaining design consistency and development speed.