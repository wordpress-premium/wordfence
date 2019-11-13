<?php if (!defined('WORDFENCE_VERSION')) { exit; } ?>
<?php
if (!wfUtils::isAdmin()) {
	exit();
}
/**
 * @var array $results
 */
?>
<table border="0" cellpadding="2" cellspacing="0" class="wf-recent-traffic-table">
	<?php foreach ($results as $key => $v) { ?>
		<tr>
			<th>Time:</th>
			<td><?php echo $v['timeAgo'] ?> ago -- <?php echo date(DATE_RFC822, $v['ctime']); ?> -- <?php echo $v['ctime']; ?> in Unixtime</td>
		</tr>
		<?php if ($v['timeSinceLastHit']) {
			echo '<th>Secs since last hit:</th><td>' . $v['timeSinceLastHit'] . '</td></tr>';
		} ?>
		<?php if (wfUtils::hasXSS($v['URL'])) { ?>
			<tr>
				<th>URL:</th>
				<td><span style="color: #F00;">Possible XSS code filtered out for your security</span></td>
			</tr>
		<?php } else { ?>
			<tr>
				<th>URL:</th>
				<td>
					<a href="<?php echo wp_kses($v['URL'], array()); ?>" target="_blank" rel="noopener noreferrer"><?php echo $v['URL']; ?></a>
				</td>
			</tr>
		<?php } ?>
		<tr>
			<th>Type:</th>
			<td><?php
                if ($v['statusCode'] == '404') {
					echo '<span style="color: #F00;">Page not found</span>';
				}
				else if ($v['type'] == 'hit') {
					echo 'Normal request';
				} ?></td>
		</tr>
		<?php if ($v['referer']) { ?>
			<tr>
			<th>Referrer:</th>
			<td>
				<a href="<?php echo $v['referer']; ?>" target="_blank" rel="noopener noreferrer"><?php echo $v['referer']; ?></a>
			</td></tr><?php } ?>
		<tr>
			<th>Full Browser ID:</th>
			<td><?php echo esc_html($v['UA'], array()); ?></td>
		</tr>
		<?php if ($v['user']) { ?>
			<tr>
				<th>User:</th>
				<td>
					<a href="<?php echo $v['user']['editLink']; ?>" target="_blank" rel="noopener noreferrer"><span data-userid="<?php echo esc_attr($v['user']['ID']); ?>" class="wfAvatar"></span><?php echo $v['user']['display_name']; ?></a>
				</td>
			</tr>
		<?php } ?>
		<?php if ($v['loc']) { ?>
			<tr>
				<th>Location:</th>
				<td>
					<span class="wf-flag <?php echo esc_attr('wf-flag-' . strtolower($v['loc']['countryCode'])); ?>" title="<?php echo esc_attr($v['loc']['countryName']); ?>"></span>
					<?php if ($v['loc']['city']) {
						echo $v['loc']['city'] . ', ';
					} ?>
					<?php echo $v['loc']['countryName']; ?>
				</td>
			</tr>
		<?php } ?>
		<tr class="wf-recent-traffic-table-row-border">
			<td colspan="2"><div></div></td>
		</tr>
	<?php } ?>

</table>
