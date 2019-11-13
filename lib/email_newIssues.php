<?php if (!defined('WORDFENCE_VERSION')) { exit; } ?>
<?php $scanOptions = $scanController->scanOptions(); ?>
<p><?php printf(__('This email was sent from your website "%s" by the Wordfence plugin.', 'wordfence'), esc_html(get_bloginfo('name', 'raw'))); ?></p>

<p><?php printf(__('Wordfence found the following new issues on "%s".', 'wordfence'), esc_html(get_bloginfo('name', 'raw'))); ?></p>

<p><?php printf(__('Alert generated at %s', 'wordfence'), esc_html(wfUtils::localHumanDate())); ?></p>

<br>

<p><?php printf(__('See the details of these scan results on your site at: %s', 'wordfence'), wfUtils::wpAdminURL('admin.php?page=WordfenceScan')); ?></p>

<?php if ($scanOptions['scansEnabled_highSense']): ?>
	<div style="margin: 12px 0;padding: 8px; background-color: #ffffe0; border: 1px solid #ffd975; border-width: 1px 1px 1px 10px;">
		<em><?php _e('HIGH SENSITIVITY scanning is enabled, it may produce false positives', 'wordfence'); ?></em>
	</div>
<?php endif ?>

<?php if (wfConfig::get('betaThreatDefenseFeed')): ?>
	<div style="margin: 12px 0;padding: 8px; background-color: #ffffe0; border: 1px solid #ffd975; border-width: 1px 1px 1px 10px;">
		<?php _e('Beta scan signatures are currently enabled. These signatures have not been fully tested yet and may cause false positives or scan stability issues on some sites.', 'wordfence'); echo ' '; _e('The Beta option can be turned off at the bottom of the Diagnostics page.', 'wordfence'); ?>
	</div>
<?php endif; ?>

<?php if ($timeLimitReached): ?>
	<div style="margin: 12px 0;padding: 8px; background-color: #ffffe0; border: 1px solid #ffd975; border-width: 1px 1px 1px 10px;">
		<em><?php printf(__('The scan was terminated early because it reached the time limit for scans. If you would like to allow your scans to run longer, you can customize the limit on the options page: <a href="%s">%s</a> or read more about scan options to improve scan speed here: <a href="%s">%s</a>', 'wordfence'), esc_attr(wfUtils::wpAdminURL('admin.php?page=WordfenceScan&subpage=scan_options#wf-scanner-options-performance')), esc_attr(wfUtils::wpAdminURL('admin.php?page=WordfenceScan&subpage=scan_options')), wfSupportController::esc_supportURL(wfSupportController::ITEM_SCAN_TIME_LIMIT), esc_html(wfSupportController::supportURL(wfSupportController::ITEM_SCAN_TIME_LIMIT))); ?></em>
	</div>
<?php endif ?>

<?php
$severitySections = array(
	wfIssues::SEVERITY_CRITICAL => __('Critical Problems:', 'wordfence'),
	wfIssues::SEVERITY_HIGH => __('High Severity Problems:', 'wordfence'),
	wfIssues::SEVERITY_MEDIUM => __('Medium Severity Problems:', 'wordfence'),
	wfIssues::SEVERITY_LOW => __('Low Severity Problems:', 'wordfence'),
);
?>

<?php
foreach ($severitySections as $severityLevel => $severityLabel):
	if ($severityLevel < $level) {
		continue;
	}
	$hasIssuesAtSeverity = false;

	foreach($issues as $i){ if($i['severity'] == $severityLevel){ ?>
<?php if (!$hasIssuesAtSeverity): $hasIssuesAtSeverity = true; ?>
<p><?php echo $severityLabel ?></p>
<?php endif ?>
<p>* <?php echo htmlspecialchars($i['shortMsg']) ?></p>
<?php
	if ((isset($i['tmplData']['wpRemoved']) && $i['tmplData']['wpRemoved']) || (isset($i['tmplData']['abandoned']) && $i['tmplData']['abandoned'])) {
		if (isset($i['tmplData']['vulnerable']) && $i['tmplData']['vulnerable']) {
			echo '<p><strong>' . __('Plugin contains an unpatched security vulnerability.', 'wordfence') . '</strong>';
			if (isset($i['tmplData']['vulnerabilityLink'])) {
				echo ' <a href="' . $i['tmplData']['vulnerabilityLink'] . '" target="_blank" rel="nofollow noreferrer noopener">' . __('Vulnerability Information', 'wordfence') . '</a>';
			}
			echo '</p>';
		}
	}
	if ($i['type'] == 'coreUnknown') {
		echo '<p>' . __('The core files scan has not run because this version is not currently indexed by Wordfence. New WordPress versions may take up to a day to be indexed.', 'wordfence') . '</p>';
	}
	else if ($i['type'] == 'wafStatus') {
		echo '<p>' . __('Firewall issues may be caused by file permission changes or other technical problems.', 'wordfence') . ' <a href="' . wfSupportController::esc_supportURL(wfSupportController::ITEM_SCAN_RESULT_WAF_DISABLED) . '" target="_blank" rel="nofollow noreferrer noopener">' . __('More Details and Instructions', 'wordfence') . '</a></p>';
    }

	$showWPParagraph = !empty($i['tmplData']['vulnerable']) || isset($i['tmplData']['wpURL']);
	if ($showWPParagraph) {
		echo '<p>';
	}
	if (!empty($i['tmplData']['vulnerable'])) {
		echo '<strong>' . __('Update includes security-related fixes.', 'wordfence') . '</strong>';
		if (isset($i['tmplData']['vulnerabilityLink'])) {
			echo ' <a href="' . $i['tmplData']['vulnerabilityLink'] . '" target="_blank" rel="nofollow noreferrer noopener">' . __('Vulnerability Information', 'wordfence') . '</a>';
		}
	}
	if (isset($i['tmplData']['wpURL'])) {
		echo $i['tmplData']['wpURL'] . '/#developers';
	}
	if ($showWPParagraph) {
		echo '</p>';
	}
	?>

<?php
if (!empty($i['tmplData']['badURL'])):
	$api = new wfAPI(wfConfig::get('apiKey'), wfUtils::getWPVersion());
	$url = set_url_scheme($api->getTextImageURL($i['tmplData']['badURL']), 'https');
?>
<p><img src="<?php echo esc_url($url) ?>" alt="The malicious URL matched" /></p>
<?php endif ?>

<?php } } ?>
<?php endforeach; ?>

<?php if ($issuesNotShown > 0) { ?>
<p><?php printf(($issuesNotShown == 1 ? __('%d issue was omitted from this email.', 'wordfence') : __('%d issues were omitted from this email.', 'wordfence')), $issuesNotShown); echo ' '; _e('View every issue:', 'wordfence'); ?> <a href="<?php echo esc_attr(wfUtils::wpAdminURL('admin.php?page=WordfenceScan')); ?>"><?php echo esc_html(wfUtils::wpAdminURL('admin.php?page=WordfenceScan')); ?></a></p>
<?php } ?>


<?php if(! $isPaid){ ?>
	<p><?php _e('NOTE: You are using the free version of Wordfence. Upgrade today:', 'wordfence'); ?></p>
	
	<ul>
		<li><?php _e('Receive real-time Firewall and Scan engine rule updates for protection as threats emerge', 'wordfence'); ?></li>
		<li><?php _e('Real-time IP Blacklist blocks the most malicious IPs from accessing your site', 'wordfence'); ?></li>
		<li><?php _e('Country blocking', 'wordfence'); ?></li>
		<li><?php _e('IP reputation monitoring', 'wordfence'); ?></li>
		<li><?php _e('Schedule scans to run more frequently and at optimal times', 'wordfence'); ?></li>
		<li><?php _e('Access to Premium Support', 'wordfence'); ?></li>
		<li><?php _e('Discounts for multi-year and multi-license purchases', 'wordfence'); ?></li>
	</ul>

	<p><?php _e('Click here to upgrade to Wordfence Premium:', 'wordfence'); ?><br><a href="https://www.wordfence.com/zz2/wordfence-signup/">https://www.wordfence.com/zz2/wordfence-signup/</a></p>
<?php } ?>

<p><!-- ##UNSUBSCRIBE## --></p>


