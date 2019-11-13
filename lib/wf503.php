<?php if (!defined('WORDFENCE_VERSION')) { exit; } ?>
<!DOCTYPE html>
<html>
	<head>
		<title><?php _e('Your access to this site has been limited', 'wordfence'); ?></title>
		<style>
			html {
				font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
				font-size: 14px;
				line-height: 1.42857143;
				color: #333;
				background-color: #fff;
			}
			
			body {
				padding: 2rem;
			}

			a {
				color:#00709e;
			}

			h1, h2, h3, h4, h45, h6 {
				font-weight: 500;
				line-height: 1.1;
			}

			h1 { font-size: 36px; }
			h2 { font-size: 30px; }
			h3 { font-size: 24px; }
			h4 { font-size: 18px; }
			h5 { font-size: 14px; }
			h6 { font-size: 12px; }

			h1, h2, h3 {
				margin-top: 20px;
				margin-bottom: 10px;
			}
			h4, h5, h6 {
				margin-top: 10px;
				margin-bottom: 10px;
			}

			.wf-btn {
				display: inline-block;
				margin-bottom: 0;
				font-weight: normal;
				text-align: center;
				vertical-align: middle;
				touch-action: manipulation;
				cursor: pointer;
				background-image: none;
				border: 1px solid transparent;
				white-space: nowrap;
				text-transform: uppercase;
				padding: .4rem 1rem;
				font-size: .875rem;
				line-height: 1.3125rem;
				border-radius: 4px;
				-webkit-user-select: none;
				-moz-user-select: none;
				-ms-user-select: none;
				user-select: none
			}

			@media (min-width: 768px) {
				.wf-btn {
					padding: .5rem 1.25rem;
					font-size: .875rem;
					line-height: 1.3125rem;
					border-radius: 4px
				}
			}

			.wf-btn:focus,
			.wf-btn.wf-focus,
			.wf-btn:active:focus,
			.wf-btn:active.wf-focus,
			.wf-btn.wf-active:focus,
			.wf-btn.wf-active.wf-focus {
				outline: 5px auto -webkit-focus-ring-color;
				outline-offset: -2px
			}

			.wf-btn:hover,
			.wf-btn:focus,
			.wf-btn.wf-focus {
				color: #00709e;
				text-decoration: none
			}

			.wf-btn:active,
			.wf-btn.wf-active {
				outline: 0;
				background-image: none;
				-webkit-box-shadow: inset 0 3px 5px rgba(0, 0, 0, 0.125);
				box-shadow: inset 0 3px 5px rgba(0, 0, 0, 0.125)
			}

			.wf-btn.wf-disabled,
			.wf-btn[disabled],
			.wf-btn[readonly],
			fieldset[disabled] .wf-btn {
				cursor: not-allowed;
				-webkit-box-shadow: none;
				box-shadow: none
			}

			a.wf-btn {
				text-decoration: none
			}

			a.wf-btn.wf-disabled,
			fieldset[disabled] a.wf-btn {
				cursor: not-allowed;
				pointer-events: none
			}

			.wf-btn-default {
				color: #00709e;
				background-color: #fff;
				border-color: #00709e
			}

			.wf-btn-default:focus,
			.wf-btn-default.focus {
				color: #00709e;
				background-color: #e6e6e6;
				border-color: #00161f
			}

			.wf-btn-default:hover {
				color: #00709e;
				background-color: #e6e6e6;
				border-color: #004561
			}

			.wf-btn-default:active,
			.wf-btn-default.active {
				color: #00709e;
				background-color: #e6e6e6;
				border-color: #004561
			}

			.wf-btn-default:active:hover,
			.wf-btn-default:active:focus,
			.wf-btn-default:active.focus,
			.wf-btn-default.active:hover,
			.wf-btn-default.active:focus,
			.wf-btn-default.active.focus {
				color: #00709e;
				background-color: #d4d4d4;
				border-color: #00161f
			}

			.wf-btn-default:active,
			.wf-btn-default.wf-active {
				background-image: none
			}

			.wf-btn-default.wf-disabled,
			.wf-btn-default[disabled],
			.wf-btn-default[readonly],
			fieldset[disabled] .wf-btn-default {
				color: #777;
				background-color: #fff;
				border-color: #e2e2e2;
				cursor: not-allowed
			}

			.wf-btn-default.wf-disabled:hover,
			.wf-btn-default.wf-disabled:focus,
			.wf-btn-default.wf-disabled.wf-focus,
			.wf-btn-default[disabled]:hover,
			.wf-btn-default[disabled]:focus,
			.wf-btn-default[disabled].wf-focus,
			.wf-btn-default[readonly]:hover,
			.wf-btn-default[readonly]:focus,
			.wf-btn-default[readonly].wf-focus,
			fieldset[disabled] .wf-btn-default:hover,
			fieldset[disabled] .wf-btn-default:focus,
			fieldset[disabled] .wf-btn-default.wf-focus {
				background-color: #fff;
				border-color: #00709e
			}

			input[type="text"], input.wf-input-text {
				text-align: left;
				max-width: 200px;
				height: 34px;
				border-radius: 0;
				border: 0;
				background-color: #ffffff;
				box-shadow: 1px 1px 1px 2px rgba(215,215,215,0.65);
				padding: 0.25rem;
			}

			hr {
				margin-top: 20px;
				margin-bottom: 20px;
				border: 0;
				border-top: 1px solid #eee
			}
			
			.wf-header-logo {
				max-width: 450px;
				max-height: 81px;
				margin-bottom: 2rem;
			}

			@media (max-width: 600px) {
				.wf-header-logo {
					max-width: 300px;
					max-height: 54px;
				}
			}
		</style>
	</head>
	<body>
		<?php
		$contents = file_get_contents(WORDFENCE_PATH . '/images/wf-horizontal.svg');
		$contents = preg_replace('/^<\?xml.+?\?>\s*/i', '', $contents);
		$contents = preg_replace('/^<!DOCTYPE.+?>\s*/i', '', $contents);
		$contents = preg_replace('/<svg\s+xmlns="[^"]*"/i', '<svg', $contents);
		$contents = preg_replace('/(<svg[^>]+)/i', '${1} class="wf-header-logo"', $contents);
		echo $contents;
		?>
		<h4><?php _e('Your access to this site has been limited', 'wordfence'); ?></h4>
		<p><?php _e('Your access to this service has been temporarily limited. Please try again in a few minutes. (HTTP response code 503)', 'wordfence'); ?></p>
		<p><?php _e('Reason:', 'wordfence'); ?> <span style="color: #c10000;"><?php echo $reason; ?></span></p>
		<?php if (!empty($customText)): ?>
		<hr>
		<div><?php echo $customText; ?></div>
		<?php endif; ?>
		<hr>
		<?php require(dirname(__FILE__) . '/wfUnlockMsg.php'); ?>
		<p><?php printf(__('Click here to learn more: <a href="%s" target="_blank" rel="noopener noreferrer">Documentation</a>', 'wordfence'), wfSupportController::esc_supportURL(wfSupportController::ITEM_LOCKED_OUT)); ?></p>
		<p style="color: #999999;margin-top: 2rem;"><em><?php printf(__('Generated by Wordfence at %s', 'wordfence'), gmdate('D, j M Y G:i:s T', wfWAFUtils::normalizedTime())); ?>.<br><?php _e('Your computer\'s time:', 'wordfence'); ?> <script type="application/javascript">document.write(new Date().toUTCString());</script>.</em></p>
	</body>
</html>
