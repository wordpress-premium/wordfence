<?php
if (!defined('WFWAF_VIEW_RENDERING')) { exit; }

/** @var wfWAF $waf */
/** @var wfWAFView $this */

/*
 * IMPORTANT:
 * 
 * If the form variables below change name or format, admin.ajaxWatcher.js in the main plugin also needs changed. It
 * processes these to generate its whitelist button.
 */

$method = wfWAFUtils::strtolower($waf->getRequest()->getMethod());
$urlParamsToWhitelist = array();
foreach ($waf->getFailedRules() as $paramKey => $categories) {
	foreach ($categories as $category => $failedRules) {
		foreach ($failedRules as $failedRule) {
			/**
			 * @var wfWAFRule $rule
			 * @var wfWAFRuleComparisonFailure $failedComparison
			 */
			$rule = $failedRule['rule'];
			$failedComparison = $failedRule['failedComparison'];

			$urlParamsToWhitelist[] = array(
				'path'     => $waf->getRequest()->getPath(),
				'paramKey' => $failedComparison->getParamKey(),
				'ruleID'   => $rule->getRuleID(),
			);
		}
	}
}


?>
<!DOCTYPE html>
<html>
<head>
	<title>403 Forbidden</title>
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
	$contents = file_get_contents(dirname(__FILE__) . '/../../../../../images/wf-horizontal.svg');
	$contents = preg_replace('/^<\?xml.+?\?>\s*/i', '', $contents);
	$contents = preg_replace('/^<!DOCTYPE.+?>\s*/i', '', $contents);
	$contents = preg_replace('/<svg\s+xmlns="[^"]*"/i', '<svg', $contents);
	$contents = preg_replace('/(<svg[^>]+)/i', '${1} class="wf-header-logo"', $contents);
	echo $contents;
	
	if (!empty($errorNonce)) { echo '<!-- WFWAF NONCE: ' . htmlentities($errorNonce) . ' -->'; }
	?>
	<h2>403 Forbidden</h2>
	
	<p>A potentially unsafe operation has been detected in your request to this site, and has been blocked by Wordfence.</p>
<?php if (!empty($customText)): ?>
	<hr>
	<div><?php echo $customText; ?></div>
<?php endif; ?>
	<hr>
	
<?php if ($urlParamsToWhitelist): ?>
	<p>If you are an administrator and you are certain this is a false positive, you can automatically whitelist this request and repeat the same action.</p>

	<form id="whitelist-form" action="<?php echo htmlentities($waf->getRequest()->getPath(), ENT_QUOTES, 'utf-8') ?>" method="post">
		<input type="hidden" name="wfwaf-false-positive-params" value="<?php echo htmlentities(wfWAFUtils::json_encode($urlParamsToWhitelist), ENT_QUOTES, 'utf-8') ?>">
		<input type="hidden" name="wfwaf-false-positive-nonce" value="<?php echo htmlentities($waf->getAuthCookieValue('nonce', ''), ENT_QUOTES, 'utf-8') ?>">

		<div id="whitelist-actions">
			<p><label><input id="verified-false-positive-checkbox" type="checkbox" name="wfwaf-false-positive-verified" value="1"> <em>I am certain this is a false positive.</em></label></p>

			<p><button id="whitelist-button" type="submit">Whitelist This Action</button></p>
		</div>

		<p id="success" style="color: #35b13a; font-weight: bold; display: none"><em>All set! You can refresh the page to try this action again.</em></p>
		<p id="error" style="color: #dd422c; font-weight: bold; display: none"><em>Something went wrong whitelisting this request. You can try setting the Firewall Status to Learning Mode under Web App Firewall in the Wordfence menu, and retry this same action.</em></p>
	</form>
	<script>
		var whitelistButton = document.getElementById('whitelist-button');
		var verified = document.getElementById('verified-false-positive-checkbox');
		verified.checked = false;
		verified.onclick = function() {
			whitelistButton.disabled = !this.checked;
		};
		verified.onclick();

		document.getElementById('whitelist-form').onsubmit = function(evt) {
			evt.preventDefault();
			var request = new XMLHttpRequest();
			request.addEventListener("load", function() {
				if (this.status === 200 && this.responseText.indexOf('Successfully whitelisted') > -1) {
					document.getElementById('whitelist-actions').style.display = 'none';
					document.getElementById('success').style.display = 'block';
				} else {
					document.getElementById('error').style.display = 'block';
				}
			});
			request.open("POST", this.action, true);
			request.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
			var inputs = this.querySelectorAll('input[name]');
			var data = '';
			for (var i = 0; i < inputs.length; i++) {
				data += encodeURIComponent(inputs[i].name) + '=' + encodeURIComponent(inputs[i].value) + '&';
			}
			request.send(data);
			return false;
		};


	</script>
	<hr>
<?php endif ?>
	
	<p style="color: #999999;margin-top: 2rem;"><em>Generated by Wordfence at <?php echo gmdate('D, j M Y G:i:s T', wfWAFUtils::normalizedTime()); ?>.<br>Your computer's time: <script type="application/javascript">document.write(new Date().toUTCString());</script>.</em></p>
</body>
</html>