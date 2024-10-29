jQuery(document).ready(function($) {
  if($('#commentform, #micro-contact-form').length > 0) {
    var special_fields_data = {
      action: 'analytical_spam_filter_form_handler'
    };

    $.post(analytical_spam_filter_ajax.url, special_fields_data, function(response) {
      $(response).appendTo('#commentform, #micro-contact-form');
    });

    var form_entry_start = 0;
    var form_entry_duration = 0;
    var duration_field_data = {
      action: 'analytical_spam_filter_duration_field_handler'
    };

    $.post(analytical_spam_filter_ajax.url, duration_field_data, function(response) {
      $('#commentform, #micro-contact-form').on('focusin', (event) => { form_entry_start = performance.now(); });
      $('#commentform, #micro-contact-form').on('focusout', (event) => { form_entry_duration += performance.now() - form_entry_start; $('[id=' + response + ']').val(form_entry_duration); });
    });
  }

  return false;
});