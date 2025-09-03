<?php
/**
 * Plugin Name: Branded Reset Emails (Advanced)
 * Description: Rebrand password reset and related emails with custom From name/email, subject brand, optional HTML template (safe-save), test email, and multisite overrides.
 * Version: 1.2.1
 * Author: Van Isle Web Solutions
 * Author URI:		https://www.vanislebc.com/
 * License: GPLv2 or later
 * Requires at least: 5.6
 * Tested up to: 6.8.2
 * Text Domain: branded-reset-emails
 */

if ( ! defined( 'ABSPATH' ) ) exit;
define( 'BREA_VER', '1.2.1' );

/** ========= Helpers ========= */
function brea_default_from_email() {
    $home = home_url();
    $host = parse_url( $home, PHP_URL_HOST );
    if ( ! $host ) return 'noreply@localhost';
    $host = preg_replace('/^www\./i', '', $host);
    return 'noreply@' . $host;
}
function brea_is_multisite_forced() {
    if ( ! is_multisite() ) return false;
    $net = get_site_option( 'brea_network_options', array() );
    return ! empty( $net['force_network'] );
}
function brea_get_option( $key, $default = '' ) {
    if ( is_multisite() && brea_is_multisite_forced() ) {
        $net = get_site_option( 'brea_network_options', array() );
        if ( isset( $net[ $key ] ) && $net[ $key ] !== '' ) return $net[ $key ];
    }
    $opts = get_option( 'brea_options', array() );
    if ( isset( $opts[ $key ] ) && $opts[ $key ] !== '' ) return $opts[ $key ];
    if ( is_multisite() ) {
        $net = get_site_option( 'brea_network_options', array() );
        if ( isset( $net[ $key ] ) && $net[ $key ] !== '' ) return $net[ $key ];
    }
    return $default;
}
function brea_bool( $val ) {
    return ( $val === '1' || $val === 1 || $val === true );
}
function brea_get_template_html() {
    $raw = brea_get_option( 'template_html', '' );
    if ( $raw === '' ) $raw = brea_default_template_html();
    if ( preg_match( '#^[A-Za-z0-9+/=\r\n]+$#', $raw ) ) {
        $decoded = base64_decode( $raw, true );
        if ( $decoded !== false && strip_tags( $decoded ) !== '' ) return $decoded;
    }
    return $raw;
}

/** ========= Admin: Site Settings ========= */
add_action( 'admin_menu', function(){
    add_options_page(
        __('Branded Emails', 'branded-reset-emails'),
        __('Branded Emails', 'branded-reset-emails'),
        'manage_options',
        'brea-settings',
        'brea_render_settings_page'
    );
});
add_action( 'admin_init', function(){
    register_setting( 'brea_options_group', 'brea_options', 'brea_sanitize_options' );
    add_settings_section( 'brea_main', __('General Settings', 'branded-reset-emails'), function(){
        if ( is_multisite() && brea_is_multisite_forced() ) {
            echo '<p><strong>'.esc_html__('Network settings are enforced. Local changes are disabled.', 'branded-reset-emails').'</strong></p>';
        } else {
            echo '<p>'.esc_html__('Customize sender, subject, and template used for password reset and related emails.', 'branded-reset-emails').'</p>';
        }
    }, 'brea-settings' );
    $disabled = ( is_multisite() && brea_is_multisite_forced() ) ? 'disabled' : '';
    add_settings_field( 'from_name', __('From Name', 'branded-reset-emails'), function() use ( $disabled ){
        $val = brea_get_option( 'from_name', get_bloginfo( 'name', 'display' ) );
        echo '<input type="text" class="regular-text" name="brea_options[from_name]" value="'.esc_attr( $val ).'" '.$disabled.'>';
    }, 'brea-settings', 'brea_main' );
    add_settings_field( 'from_email', __('From Email', 'branded-reset-emails'), function() use ( $disabled ){
        $val = brea_get_option( 'from_email', brea_default_from_email() );
        echo '<input type="email" class="regular-text" name="brea_options[from_email]" value="'.esc_attr( $val ).'" '.$disabled.'>';
        echo '<p class="description">'.esc_html__('Use an address on your domain with SPF/DKIM configured.', 'branded-reset-emails').'</p>';
    }, 'brea-settings', 'brea_main' );
    add_settings_field( 'subject_brand', __('Subject Brand/Prefix', 'branded-reset-emails'), function() use ( $disabled ){
        $default = get_bloginfo( 'name', 'display' );
        if ( ! $default ) $default = wp_parse_url( home_url(), PHP_URL_HOST );
        $val = brea_get_option( 'subject_brand', $default );
        echo '<input type="text" class="regular-text" name="brea_options[subject_brand]" value="'.esc_attr( $val ).'" '.$disabled.'>';
        echo '<p class="description">'.esc_html__('Appears like [Your Brand] Password Reset', 'branded-reset-emails').'</p>';
    }, 'brea-settings', 'brea_main' );
    add_settings_field( 'enable_html', __('Use HTML Template', 'branded-reset-emails'), function() use ( $disabled ){
        $val = brea_get_option( 'enable_html', '0' );
        echo '<label><input type="checkbox" name="brea_options[enable_html]" value="1" '.checked( $val, '1', false ).' '.$disabled.'> ';
        echo esc_html__('Send password reset and confirmations as HTML using the template below.', 'branded-reset-emails').'</label>';
    }, 'brea-settings', 'brea_main' );
    add_settings_field( 'template_html', __('HTML Template', 'branded-reset-emails'), function() use ( $disabled ){
        $val = brea_get_template_html();
        echo '<textarea id="brea-template-html" rows="12" cols="80" name="brea_options[template_html]" '.$disabled.'>'.esc_textarea( $val ).'</textarea>';
        echo '<p class="description">'.esc_html__('Placeholders: {{brand}}, {{username}}, {{reset_url}}, {{body_intro}}, {{closing}}', 'branded-reset-emails').'</p>';
        echo '<p class="description">'.esc_html__('Safe Save Mode: template is base64-encoded on save to prevent web firewalls from blocking HTML in requests.', 'branded-reset-emails').'</p>';
    }, 'brea-settings', 'brea_main' );
    add_settings_field( 'rebrand_other', __('Rebrand other core emails', 'branded-reset-emails'), function() use ( $disabled ){
        $val = brea_get_option( 'rebrand_other', '1' );
        echo '<label><input type="checkbox" name="brea_options[rebrand_other]" value="1" '.checked( $val, '1', false ).' '.$disabled.'> ';
        echo esc_html__('Also rebrand the “password changed” and “email changed” confirmations.', 'branded-reset-emails').'</label>';
    }, 'brea-settings', 'brea_main' );
});
function brea_sanitize_options( $opts ) {
    $clean = array();
    $clean['from_name']     = isset($opts['from_name']) ? sanitize_text_field( $opts['from_name'] ) : '';
    $clean['from_email']    = isset($opts['from_email']) ? sanitize_email( $opts['from_email'] ) : '';
    $clean['subject_brand'] = isset($opts['subject_brand']) ? sanitize_text_field( $opts['subject_brand'] ) : '';
    $clean['enable_html']   = ! empty($opts['enable_html']) ? '1' : '0';
    $tpl = isset($opts['template_html']) ? $opts['template_html'] : '';
    if ( $tpl !== '' ) {
        if ( preg_match( '#^[A-Za-z0-9+/=\r\n]+$#', $tpl ) && base64_decode( $tpl, true ) !== false ) {
            $clean['template_html'] = $tpl;
        } else {
            $clean['template_html'] = base64_encode( wp_kses_post( $tpl ) );
        }
    } else {
        $clean['template_html'] = '';
    }
    $clean['rebrand_other'] = ! empty($opts['rebrand_other']) ? '1' : '0';
    return $clean;
}
function brea_render_settings_page(){
    if ( ! current_user_can( 'manage_options' ) ) return;
    $ajax_nonce = wp_create_nonce('brea_test_email');
    $preview_url = admin_url('admin-ajax.php?action=brea_preview_html&nonce=' . wp_create_nonce('brea_preview_html'));
    ?>
    <div class="wrap">
        <h1><?php esc_html_e('Branded Emails', 'branded-reset-emails'); ?></h1>
        <?php settings_errors('brea_options');  // show messages only for our option
 ?>
        <form id="brea-form" action="options.php" method="post">
            <?php
                settings_fields( 'brea_options_group' );
                do_settings_sections( 'brea-settings' );
                submit_button();
            ?>
        </form>
        <h2><?php esc_html_e('Tools', 'branded-reset-emails'); ?></h2>
        <p>
            <a class="button button-secondary" href="<?php echo esc_url( $preview_url ); ?>" target="_blank"><?php esc_html_e('Preview HTML Template', 'branded-reset-emails'); ?></a>
            <button id="brea-send-test" class="button button-primary"><?php esc_html_e('Send Test Email to Me', 'branded-reset-emails'); ?></button>
        </p>
        <div id="brea-test-result"></div>
    </div>
    <script>
    (function(){
        const form = document.getElementById('brea-form');
        form.addEventListener('submit', function(){
            const ta = document.getElementById('brea-template-html');
            if (ta && typeof btoa === 'function') {
                try {
                    const encoded = btoa(unescape(encodeURIComponent(ta.value)));
                    ta.value = encoded;
                } catch(e) {}
            }
        });
        const btn = document.getElementById('brea-send-test');
        if (!btn) return;
        btn.addEventListener('click', function(e){
            e.preventDefault();
            btn.disabled = true;
            const target = document.getElementById('brea-test-result');
            target.textContent = 'Sending...';
            fetch(ajaxurl, {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: new URLSearchParams({
                    action: 'brea_send_test',
                    nonce: '<?php echo esc_js( $ajax_nonce ); ?>'
                })
            }).then(r=>r.json()).then(data=>{
                target.textContent = data.message || 'Done.';
                btn.disabled = false;
            }).catch(err=>{
                target.textContent = 'Error sending test.';
                btn.disabled = false;
            });
        });
    })();
    </script>
    <?php
}

/** ========= Admin: Network Settings ========= */
if ( is_multisite() ) {
    add_action( 'network_admin_menu', function(){
        add_submenu_page(
            'settings.php',
            __('Branded Emails (Network)', 'branded-reset-emails'),
            __('Branded Emails', 'branded-reset-emails'),
            'manage_network_options',
            'brea-network-settings',
            'brea_render_network_settings'
        );
    });
    add_action( 'network_admin_edit_brea_save_network', function(){
        if ( ! current_user_can('manage_network_options') ) wp_die('Permission denied');
        check_admin_referer( 'brea_net_save' );
        $opts = array();
        $opts['from_name']     = isset($_POST['brea_network']['from_name']) ? sanitize_text_field($_POST['brea_network']['from_name']) : '';
        $opts['from_email']    = isset($_POST['brea_network']['from_email']) ? sanitize_email($_POST['brea_network']['from_email']) : '';
        $opts['subject_brand'] = isset($_POST['brea_network']['subject_brand']) ? sanitize_text_field($_POST['brea_network']['subject_brand']) : '';
        $opts['enable_html']   = ! empty($_POST['brea_network']['enable_html']) ? '1' : '0';
        $tpl                    = isset($_POST['brea_network']['template_html']) ? $_POST['brea_network']['template_html'] : '';
        $opts['template_html']  = $tpl ? base64_encode( wp_kses_post( $tpl ) ) : '';
        $opts['rebrand_other'] = ! empty($_POST['brea_network']['rebrand_other']) ? '1' : '0';
        $opts['force_network'] = ! empty($_POST['brea_network']['force_network']) ? '1' : '0';
        update_site_option( 'brea_network_options', $opts );
        wp_redirect( add_query_arg( array('page'=>'brea-network-settings','updated'=>'1'), network_admin_url('settings.php') ) );
        exit;
    });
    function brea_render_network_settings(){
        if ( ! current_user_can('manage_network_options') ) return;
        $opts = get_site_option( 'brea_network_options', array() );
        $tpl  = isset($opts['template_html']) ? base64_decode( $opts['template_html'], true ) : '';
        if ( ! $tpl ) $tpl = brea_default_template_html();
        ?>
        <div class="wrap">
            <h1><?php esc_html_e('Branded Emails (Network)', 'branded-reset-emails'); ?></h1>
            <?php if ( isset($_GET['updated']) ) echo '<div class="updated notice"><p>Settings saved.</p></div>'; ?>
            <form method="post" action="<?php echo esc_url( network_admin_url('edit.php?action=brea_save_network') ); ?>">
                <?php wp_nonce_field( 'brea_net_save' ); ?>
                <table class="form-table" role="presentation">
                    <tr><th><label><?php esc_html_e('From Name','branded-reset-emails'); ?></label></th>
                        <td><input type="text" class="regular-text" name="brea_network[from_name]" value="<?php echo esc_attr( isset($opts['from_name'])?$opts['from_name']:'' ); ?>"></td></tr>
                    <tr><th><label><?php esc_html_e('From Email','branded-reset-emails'); ?></label></th>
                        <td><input type="email" class="regular-text" name="brea_network[from_email]" value="<?php echo esc_attr( isset($opts['from_email'])?$opts['from_email']:'' ); ?>">
                        <p class="description"><?php esc_html_e('Use an address on a domain with SPF/DKIM.', 'branded-reset-emails'); ?></p></td></tr>
                    <tr><th><label><?php esc_html_e('Subject Brand/Prefix','branded-reset-emails'); ?></label></th>
                        <td><input type="text" class="regular-text" name="brea_network[subject_brand]" value="<?php echo esc_attr( isset($opts['subject_brand'])?$opts['subject_brand']:'' ); ?>"></td></tr>
                    <tr><th><?php esc_html_e('Use HTML Template','branded-reset-emails'); ?></th>
                        <td><label><input type="checkbox" name="brea_network[enable_html]" value="1" <?php checked( isset($opts['enable_html'])?$opts['enable_html']:'0', '1' ); ?>> <?php esc_html_e('Enable HTML for network defaults/forced.', 'branded-reset-emails'); ?></label></td></tr>
                    <tr><th><label><?php esc_html_e('HTML Template','branded-reset-emails'); ?></label></th>
                        <td><textarea rows="12" cols="80" name="brea_network[template_html]"><?php echo esc_textarea( $tpl ); ?></textarea>
                        <p class="description"><?php esc_html_e('Placeholders: {{brand}}, {{username}}, {{reset_url}}, {{body_intro}}, {{closing}}', 'branded-reset-emails'); ?></p></td></tr>
                    <tr><th><?php esc_html_e('Rebrand other core emails','branded-reset-emails'); ?></th>
                        <td><label><input type="checkbox" name="brea_network[rebrand_other]" value="1" <?php checked( isset($opts['rebrand_other'])?$opts['rebrand_other']:'0', '1' ); ?>> <?php esc_html_e('Password changed & email changed confirmations.', 'branded-reset-emails'); ?></label></td></tr>
                    <tr><th><?php esc_html_e('Force Network Settings','branded-reset-emails'); ?></th>
                        <td><label><input type="checkbox" name="brea_network[force_network]" value="1" <?php checked( isset($opts['force_network'])?$opts['force_network']:'0', '1' ); ?>> <?php esc_html_e('Override and lock settings on all subsites.', 'branded-reset-emails'); ?></label></td></tr>
                </table>
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }
}

/** ========= AJAX: Test + Preview ========= */
add_action( 'wp_ajax_brea_send_test', function(){
    if ( ! current_user_can('manage_options') ) wp_send_json_error( array('message'=>'Permission denied') );
    check_ajax_referer( 'brea_test_email', 'nonce' );
    $user = wp_get_current_user();
    if ( ! $user || ! $user->user_email ) wp_send_json_error( array('message'=>'No user email found.') );
    $brand = brea_get_option( 'subject_brand', get_bloginfo('name','display') );
    if ( ! $brand ) $brand = wp_parse_url( home_url(), PHP_URL_HOST );
    $from_name  = brea_get_option( 'from_name', $brand );
    $from_email = brea_get_option( 'from_email', brea_default_from_email() );
    $enable_html = brea_get_option( 'enable_html', '0' );
    $template = brea_get_template_html();
    $reset_url = wp_login_url() . '?action=rp&key=demo&login=' . rawurlencode( $user->user_login );
    $subject = '['.$brand.'] Password Reset (Test Preview — Link is not functional)';
    $headers = array( 'From: ' . $from_name . ' <' . $from_email . '>' );
    $message = brea_build_message( $enable_html === '1', $template, array(
        'brand' => $brand,
        'username' => $user->user_login,
        'reset_url' => $reset_url,
        'body_intro' => 'This is a test preview of your branded password reset template. The link below is not a real reset link.',
        'closing' => '— ' . $from_name
    ) );
    if ( $enable_html === '1' ) add_filter( 'wp_mail_content_type', 'brea_content_type_html', 20 );
    $ok = wp_mail( $user->user_email, $subject, $message, $headers );
    if ( $enable_html === '1' ) remove_filter( 'wp_mail_content_type', 'brea_content_type_html', 20 );
    if ( $ok ) wp_send_json_success( array('message'=>'Test email sent to ' . $user->user_email ) );
    wp_send_json_error( array('message'=>'Failed to send; check mail logs/SMTP settings.') );
});
add_action( 'wp_ajax_brea_preview_html', function(){
    if ( ! current_user_can('manage_options') ) wp_die('Permission denied');
    if ( ! isset($_GET['nonce']) || ! wp_verify_nonce( $_GET['nonce'], 'brea_preview_html' ) ) wp_die('Bad nonce');
    $brand = brea_get_option( 'subject_brand', get_bloginfo('name','display') );
    if ( ! $brand ) $brand = wp_parse_url( home_url(), PHP_URL_HOST );
    $user = wp_get_current_user();
    $template = brea_get_template_html();
    $html = brea_build_message( true, $template, array(
        'brand' => $brand,
        'username' => $user ? $user->user_login : 'username',
        'reset_url' => wp_login_url() . '?action=rp&key=demo&login=' . rawurlencode( $user ? $user->user_login : 'username' ),
        'body_intro' => 'A password reset was requested for your account at ' . $brand . '. (Preview — Link is not functional)',
        'closing' => '— ' . ( brea_get_option('from_name',$brand) )
    ) );
    header('Content-Type: text/html; charset=utf-8');
    echo $html; exit;
});
function brea_content_type_html( $type ){ return 'text/html'; }

/** ========= Template Builder ========= */
function brea_default_template_html(){
    $brand = get_bloginfo('name','display');
    if ( ! $brand ) $brand = wp_parse_url( home_url(), PHP_URL_HOST );
    $logo = esc_url( get_site_icon_url( 64 ) );
    $style = 'margin:0;padding:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#f6f7f8;';
    $card  = 'max-width:600px;margin:24px auto;background:#ffffff;border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,0.06);overflow:hidden;';
    $btn   = 'display:inline-block;padding:12px 18px;text-decoration:none;border-radius:8px;border:1px solid #d0d7de;';
    $html = '<!doctype html><html><head><meta charset="utf-8"><title>'.$brand.' Password Reset</title></head><body style="'.$style.'">
    <div style="'.$card.'">
      <div style="padding:20px 24px;border-bottom:1px solid #eee;display:flex;align-items:center;gap:12px;">
        '.( $logo ? '<img src="'.$logo.'" alt="'.$brand.'" width="32" height="32" style="border-radius:6px;"/>' : '' ).'
        <strong style="font-size:16px">'.$brand.'</strong>
      </div>
      <div style="padding:24px;">
        <p style="font-size:16px;margin:0 0 12px 0;">Hello <strong>{{username}}</strong>,</p>
        <p style="margin:0 0 16px 0;">{{body_intro}}</p>
        <p style="margin:0 0 20px 0;">Click the button below to reset your password:</p>
        <p><a href="{{reset_url}}" style="'.$btn.'background:#0a66c2;color:#fff;">Reset Password</a></p>
        <p style="margin:16px 0 0 0;">If the button doesn’t work, copy and paste this link:</p>
        <p style="word-break:break-all;"><a href="{{reset_url}}">{{reset_url}}</a></p>
        <p style="margin:24px 0 0 0;">{{closing}}</p>
      </div>
    </div>
    <p style="text-align:center;color:#6b7280;font-size:12px;">If you didn’t request this, you can safely ignore this email.</p>
    </body></html>';
    return $html;
}
function brea_build_message( $html_enabled, $template_html, $vars ) {
    if ( ! $html_enabled ) {
        $lines = array();
        $lines[] = "Hello " . ($vars['username'] ?? 'user') . ",";
        $lines[] = "";
        $lines[] = $vars['body_intro'] ?? 'A password reset was requested.';
        $lines[] = "";
        $lines[] = "Reset link: " . ($vars['reset_url'] ?? '');
        $lines[] = "";
        $lines[] = $vars['closing'] ?? '';
        return implode("\n", $lines);
    }
    $search  = array('{{brand}}','{{username}}','{{reset_url}}','{{body_intro}}','{{closing}}');
    $replace = array($vars['brand'] ?? '', $vars['username'] ?? '', $vars['reset_url'] ?? '', $vars['body_intro'] ?? '', $vars['closing'] ?? '');
    return str_replace( $search, $replace, $template_html );
}

/** ========= Mail Filters ========= */
add_filter( 'wp_mail_from', function( $email ) {
    $custom = brea_get_option( 'from_email', '' );
    if ( $custom ) return $custom;
    if ( ! empty( $email ) && strtolower( $email ) !== 'wordpress@' . wp_parse_url( home_url(), PHP_URL_HOST ) ) return $email;
    return brea_default_from_email();
}, 9 );
add_filter( 'wp_mail_from_name', function( $name ) {
    $custom = brea_get_option( 'from_name', '' );
    if ( $custom ) return $custom;
    if ( ! empty( $name ) && strtolower( $name ) !== 'wordpress' ) return $name;
    $site_name = get_bloginfo( 'name', 'display' );
    return $site_name ? $site_name : 'Site Team';
}, 9 );
add_filter( 'retrieve_password_title', function( $title ) {
    $brand = brea_get_option( 'subject_brand', '' );
    if ( ! $brand ) {
        $brand = get_bloginfo( 'name', 'display' );
        if ( ! $brand ) $brand = wp_parse_url( home_url(), PHP_URL_HOST );
    }
    return sprintf('[%s] Password Reset', $brand );
}, 10, 1 );
add_filter( 'retrieve_password_message', function( $message, $key, $user_login, $user_data ) {
    $brand = brea_get_option( 'subject_brand', '' );
    if ( ! $brand ) {
        $brand = get_bloginfo( 'name', 'display' );
        if ( ! $brand ) $brand = wp_parse_url( home_url(), PHP_URL_HOST );
    }
    $from_name = brea_get_option( 'from_name', $brand );
    $enable_html = brea_get_option( 'enable_html', '0' ) === '1';
    $template = brea_get_template_html();
    $reset_url = network_site_url( "wp-login.php?action=rp&key=$key&login=" . rawurlencode( $user_login ), 'login' );
    if ( $enable_html ) add_filter( 'wp_mail_content_type', 'brea_content_type_html', 20 );
    $msg = brea_build_message( $enable_html, $template, array(
        'brand' => $brand,
        'username' => $user_login,
        'reset_url' => $reset_url,
        'body_intro' => 'A password reset was requested for your account at ' . $brand . '.',
        'closing' => '— ' . $from_name
    ) );
    if ( $enable_html ) return $msg;
    return $msg;
}, 10, 4 );
add_filter( 'password_change_email', function( $pass_change_email, $user, $userdata ) {
    if ( ! brea_bool( brea_get_option( 'rebrand_other', '1' ) ) ) return $pass_change_email;
    $brand = brea_get_option( 'subject_brand', '' );
    if ( ! $brand ) $brand = get_bloginfo( 'name', 'display' );
    if ( ! $brand ) $brand = wp_parse_url( home_url(), PHP_URL_HOST );
    $from_name = brea_get_option( 'from_name', $brand );
    $enable_html = brea_get_option( 'enable_html', '0' ) === '1';
    $template = brea_get_template_html();
    $pass_change_email['subject'] = sprintf('[%s] Your password was changed', $brand );
    if ( $enable_html ) {
        add_filter( 'wp_mail_content_type', 'brea_content_type_html', 20 );
        $pass_change_email['message'] = brea_build_message( true, $template, array(
            'brand' => $brand,
            'username' => $user->user_login,
            'reset_url' => wp_login_url(),
            'body_intro' => 'This is a confirmation that your password on ' . $brand . ' has been changed.',
            'closing' => '— ' . $from_name
        ) );
    } else {
        $pass_change_email['message'] =
            "Hello " . $user->user_login . ",\n\n" .
            "This is a confirmation that your password on $brand has been changed.\n\n" .
            "If you didn’t make this change, please reset your password immediately.\n\n" .
            "— $from_name";
    }
    return $pass_change_email;
}, 10, 3 );
add_filter( 'email_change_email', function( $email_change_email, $user, $userdata ) {
    if ( ! brea_bool( brea_get_option( 'rebrand_other', '1' ) ) ) return $email_change_email;
    $brand = brea_get_option( 'subject_brand', '' );
    if ( ! $brand ) $brand = get_bloginfo( 'name', 'display' );
    if ( ! $brand ) $brand = wp_parse_url( home_url(), PHP_URL_HOST );
    $from_name = brea_get_option( 'from_name', $brand );
    $enable_html = brea_get_option( 'enable_html', '0' ) === '1';
    $template = brea_get_template_html();
    $email_change_email['subject'] = sprintf('[%s] Your email address was changed', $brand );
    if ( $enable_html ) {
        add_filter( 'wp_mail_content_type', 'brea_content_type_html', 20 );
        $email_change_email['message'] = brea_build_message( true, $template, array(
            'brand' => $brand,
            'username' => $user->user_login,
            'reset_url' => wp_login_url(),
            'body_intro' => 'This is a confirmation that your account email address on ' . $brand . ' has been changed.',
            'closing' => '— ' . $from_name
        ) );
    } else {
        $email_change_email['message'] =
            "Hello " . $user->user_login . ",\n\n" .
            "This is a confirmation that your account email address on $brand has been changed.\n\n" .
            "If you didn’t make this change, please update your password and contact an admin.\n\n" .
            "— " . $from_name;
    }
    return $email_change_email;
}, 10, 3 );
