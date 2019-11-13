<?php
if (!defined('WORDFENCE_VERSION')) { exit; }
?>
<div id="wf-toupp-required-overlay"></div>
<div id="wf-toupp-required-message">
	<div id="wf-toupp-required-message-inner">
		<p><?php _e('To continue using Wordfence, you will need to review and accept the Terms of Use and Privacy Policy. Click Resume Installation to begin.', 'wordfence'); ?></p>
		<p><a href="#" class="wf-btn wf-btn-default" onclick="window.location = jQuery('#wf-onboarding-resume').attr('href'); return false;"><?php _e('Resume Installation', 'wordfence'); ?></a></p>
	</div>
</div>
