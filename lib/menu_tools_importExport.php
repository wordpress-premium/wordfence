<?php
if (!defined('WORDFENCE_VERSION')) { exit; }
?>
<script type="application/javascript">
	(function($) {
		$(function() {
			document.title = "<?php esc_attr_e('Import/Export Options', 'wordfence'); ?>" + " \u2039 " + WFAD.basePageName;
		});
	})(jQuery);
</script>
<div id="wf-tools-importexport">
	<div class="wf-section-title">
		<h2><?php _e('Import/Export Options', 'wordfence') ?></h2>
		<span><?php printf(__('<a href="%s" target="_blank" rel="noopener noreferrer" class="wf-help-link">Learn more<span class="wf-hidden-xs"> about importing and exporting options</span></a>', 'wordfence'), wfSupportController::esc_supportURL(wfSupportController::ITEM_TOOLS_IMPORT_EXPORT)); ?>
			<i class="wf-fa wf-fa-external-link" aria-hidden="true"></i></span>
	</div>
	
	<p><?php _e("To clone one site's configuration to another, use the import/export tools below.", 'wordfence') ?></p>
	
	<?php
	echo wfView::create('dashboard/options-group-import', array(
		'stateKey' => 'global-options-import',
		'collapseable' => false,
	))->render();
	?>
</div>
