<?php

abstract class wfBaseAlert {

	public abstract function send();
}

class wfBlockAlert extends wfBaseAlert {

	private $IP;
	private $reason;
	private $secsToGo;


	/**
	 * wfBlockAlert constructor.
	 * @param $IP
	 * @param $reason
	 * @param $secsToGo
	 */
	public function __construct($IP, $reason, $secsToGo) {
		$this->IP = $IP;
		$this->reason = $reason;
		$this->secsToGo = $secsToGo;
	}

	public function send() {
		if (wfConfig::get('alertOn_block')) {
			$message = sprintf(__('Wordfence has blocked IP address %s.', 'wordfence'), $this->IP) . "\n";
			$message .= sprintf(__('The reason is: "%s".', 'wordfence'), $this->reason);
			if ($this->secsToGo > 0) {
				$message .= "\n" . sprintf(__('The duration of the block is %s.', 'wordfence'), wfUtils::makeDuration($this->secsToGo, true));
			}
			wordfence::alert(sprintf(__('Blocking IP %s', 'wordfence'), $this->IP), $message, $this->IP);
		}
	}

}

class wfAutoUpdatedAlert extends wfBaseAlert {

	private $version;

	/**
	 * @param $version
	 */
	public function __construct($version) {
		$this->version = $version;
	}

	public function send() {
		if (wfConfig::get('alertOn_update') == '1' && $this->version) {
			wordfence::alert("Wordfence Upgraded to version " . $this->version, "Your Wordfence installation has been upgraded to version " . $this->version, '127.0.0.1');
		}
	}

}

class wfWafDeactivatedAlert extends wfBaseAlert {

	private $username;
	private $IP;

	/**
	 * @param $username
	 * @param $IP
	 */
	public function __construct($username, $IP) {
		$this->username = $username;
		$this->IP = $IP;
	}

	public function send() {
		if (wfConfig::get('alertOn_wafDeactivated')) {
			wordfence::alert(__('Wordfence WAF Deactivated', 'wordfence'), sprintf(__('A user with username "%s" deactivated the Wordfence Web Application Firewall on your WordPress site.', 'wordfence'), $this->username), $this->IP);
		}
	}

}

class wfWordfenceDeactivatedAlert extends wfBaseAlert {
	private $username;
	private $IP;

	/**
	 * @param $username
	 * @param $IP
	 */
	public function __construct($username, $IP) {
		$this->username = $username;
		$this->IP = $IP;
	}

	public function send() {
		if (wfConfig::get('alertOn_wordfenceDeactivated')) {
			wordfence::alert("Wordfence Deactivated", "A user with username \"$this->username\" deactivated Wordfence on your WordPress site.", $this->IP);
		}
	}

}

class wfLostPasswdFormAlert extends wfBaseAlert {

	private $user;
	private $IP;

	/**
	 * @param $user
	 * @param $IP
	 */
	public function __construct($user, $IP) {
		$this->user = $user;
		$this->IP = $IP;
	}

	public function send() {
		if (wfConfig::get('alertOn_lostPasswdForm')) {
			wordfence::alert("Password recovery attempted", "Someone tried to recover the password for user with email address: " . wp_kses($this->user->user_email, array()), $this->IP);
		}
	}

}

class wfLoginLockoutAlert extends wfBaseAlert {

	private $IP;
	private $reason;

	/**
	 * @param $IP
	 * @param $reason
	 */
	public function __construct($IP, $reason) {
		$this->IP = $IP;
		$this->reason = $reason;
	}

	public function send() {
		if (wfConfig::get('alertOn_loginLockout')) {
			$message = sprintf(__('A user with IP addr %s has been locked out from signing in or using the password recovery form for the following reason: %s.', 'wordfence'), $this->IP, $this->reason);
			if (wfBlock::lockoutDuration() > 0) {
				$message .= "\n" . sprintf(__('The duration of the lockout is %s.', 'wordfence'), wfUtils::makeDuration(wfBlock::lockoutDuration(), true));
			}
			wordfence::alert(__('User locked out from signing in', 'wordfence'), $message, $this->IP);
		}
	}
}

class wfAdminLoginAlert extends wfBaseAlert {

	private $cookieName;
	private $username;
	private $IP;
	private $cookieValue;

	/**
	 * @param $cookieName
	 * @param $cookieValue
	 * @param $username
	 * @param $IP
	 */
	public function __construct($cookieName, $cookieValue, $username, $IP) {
		$this->cookieName = $cookieName;
		$this->cookieValue = $cookieValue;
		$this->username = $username;
		$this->IP = $IP;
	}

	public function send() {
		if (wfConfig::get('alertOn_adminLogin')) {
			$shouldAlert = true;
			if (wfConfig::get('alertOn_firstAdminLoginOnly') && isset($_COOKIE[$this->cookieName])) {
				$shouldAlert = !hash_equals($this->cookieValue, $_COOKIE[$this->cookieName]);
			}

			if ($shouldAlert) {
				wordfence::alert("Admin Login", "A user with username \"$this->username\" who has administrator access signed in to your WordPress site.", $this->IP);
			}
		}
	}
}

class wfNonAdminLoginAlert extends wfBaseAlert {

	private $cookieName;
	private $username;
	private $IP;
	private $cookieValue;

	/**
	 * @param $cookieName
	 * @param $cookieValue
	 * @param $username
	 * @param $IP
	 */
	public function __construct($cookieName, $cookieValue, $username, $IP) {
		$this->cookieName = $cookieName;
		$this->cookieValue = $cookieValue;
		$this->username = $username;
		$this->IP = $IP;
	}

	public function send() {
		if (wfConfig::get('alertOn_nonAdminLogin')) {
			$shouldAlert = true;
			if (wfConfig::get('alertOn_firstNonAdminLoginOnly') && isset($_COOKIE[$this->cookieName])) {
				$shouldAlert = !hash_equals($this->cookieValue, $_COOKIE[$this->cookieName]);
			}

			if ($shouldAlert) {
				wordfence::alert("User login", "A non-admin user with username \"$this->username\" signed in to your WordPress site.", $this->IP);
			}
		}
	}
}

class wfBreachLoginAlert extends wfBaseAlert {

	private $username;
	private $lostPasswordUrl;
	private $supportUrl;
	private $IP;

	/**
	 * @param $username
	 * @param $lostPasswordUrl
	 * @param $supportUrl
	 * @param $IP
	 */
	public function __construct($username, $lostPasswordUrl, $supportUrl, $IP) {
		$this->username = $username;
		$this->lostPasswordUrl = $lostPasswordUrl;
		$this->supportUrl = $supportUrl;
		$this->IP = $IP;
	}

	public function send() {
		if (wfConfig::get('alertOn_breachLogin')) {
			wordfence::alert(__('User login blocked for insecure password', 'wordfence'), sprintf(__('A user with username "%s" tried to sign in to your WordPress site. Access was denied because the password being used exists on lists of passwords leaked in data breaches. Attackers use such lists to break into sites and install malicious code. Please change or reset the password (%s) to reactivate this account. Learn More: %s', 'wordfence'), $this->username, $this->lostPasswordUrl, $this->supportUrl), $this->IP);
		}
	}
}

class wfIncreasedAttackRateAlert extends wfBaseAlert {

	private $message;

	/**
	 * @param $message
	 */
	public function __construct($message) {
		$this->message = $message;
	}

	public function send() {
		wordfence::alert('Increased Attack Rate', $this->message, false);
	}
}
