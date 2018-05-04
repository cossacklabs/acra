$(document).ready(function () {
    $.views.settings.delimiters("{-", "-}");
    var options = [];
    $.each(configParams.Config, function (i, item) {
        options.push(item);
    });
    var tpl = $($.templates('#settingsTplRow').render({
        options: options
    }));
    tpl.appendTo($('#v-pills-settings'));

    // set checkox values
    $.each(configParams['Config'], function (i, item) {
        if (item.input_type == 'radio') {
            if (currentConfig[item.name] == undefined) {
                $('#v-pills-settings').find('input[type="radio"][name="' + item.name + '"][value="' + item.value + '"]').attr('checked', 'checked');
            }
            else {
                var v = currentConfig[item.name] ? 1 : 0;
                $('#v-pills-settings').find('input[type="radio"][name="' + item.name + '"][value="' + currentConfig[item.name] + '"]').attr('checked', 'checked');
            }
        }
        else {
            $('#v-pills-settings').find('input[name="' + item.name + '"]').val(currentConfig[item.name]);
        }
    });

    $('#v-pills-tab a').on('click', function (e) {
        e.preventDefault();
        $(this).tab('show');
    })
});

var save = function () {
    var data = {};
    $.each(configParams['Config'], function (i, item) {
        if (item.input_type == 'radio') {
            data[item.name] = $('#v-pills-settings').find('input:checked[type="radio"][name="' + item.name + '"]').val();
        }
        else {
            data[item.name] = $('#v-pills-settings').find('input[name="' + item.name + '"]').val();
        }
    });

    $.ajax({
        method: 'POST',
        url: "/acra-server/submit_setting",
        data: data
    }).done(function () {
        $(this).addClass("done");
    });
};
