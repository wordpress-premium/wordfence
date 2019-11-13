<?php
if (!defined('WORDFENCE_LS_VERSION')) { exit; }
/**
 * @var string $ip The requesting IP. Required.
 * @var string $siteName The site name. Required.
 * @var string $siteURL The site URL. Required.
 * @var string $verificationURL The verification URL. Required.
 * @var bool $canEnable2FA Whether or not the user this is being sent to can enable 2FA. Optional
 */
?>
<strong><?php printf(__('Please verify a login attempt for your account on <a href="%s"><strong>%s</strong></a>.', 'wordfence-ls'), esc_url($siteURL), esc_html($siteName)); ?></strong>
<br><br>
<?php echo '<strong>' . __('Request Time:', 'wordfence-ls') . '</strong> ' . esc_html(\WordfenceLS\Controller_Time::format_local_time('F j, Y h:i:s A')); ?><br>
<?php echo '<strong>' . __('IP:', 'wordfence-ls') . '</strong> ' . esc_html($ip); ?>
<br><br>
<?php _e('The request was flagged as suspicious, and we need verification that you attempted to log in to allow it to proceed. This verification link <b>will be valid for 15 minutes</b> from the time it was sent. If you did not attempt this login, please change your password immediately.', 'wordfence-ls'); ?>
<br><br>
<?php if (isset($canEnable2FA) && $canEnable2FA): ?>
<?php _e('You may bypass this verification step permanently by enabling two-factor authentication on your account.', 'wordfence-ls'); ?>
<br><br>
<?php endif; ?>
<?php printf(__('<a href="%s"><b>Verify and Log In</b></a>', 'wordfence-ls'), esc_url($verificationURL)); ?>
