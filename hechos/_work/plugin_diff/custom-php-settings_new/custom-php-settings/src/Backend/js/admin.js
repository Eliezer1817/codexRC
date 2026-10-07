(($) => {
    $(document).ready(() => {
        function setupEditor(id) {
            if (wp.codeEditor) {
                $('.CodeMirror').remove()
                const editor = $(id)
                if (editor.length) {
                    let editorSettings = wp.codeEditor.defaultSettings ? _.clone(wp.codeEditor.defaultSettings) : {}
                    editorSettings.codemirror = _.extend(
                        {},
                        editorSettings.codemirror,
                        {
                            indentUnit: 2,
                            tabSize: 2,
                            mode: 'shell',
                            readOnly: !!$(editor).prop('readonly'),
                        }
                    )
                    wp.codeEditor.initialize(editor, editorSettings)
                }
            }
        }
        setupEditor('#code_editor_custom_php_settings')
        
        // Handle searching in settings table.
        $.fn.copyToClipboard = (text) => {
            text = text.replace(/\n/g, "\r\n")
            const $temp = $('<textarea>')
            $('body').append($temp)
            $temp.val(text).select()
            document.execCommand('copy')
            $temp.remove()
        }
        $('.custom-php-settings-table td:nth-child(4) span').click(function () {
            const tds = $(this).parents('tr').find('td')
            const cp = tds[0].innerHTML + '=' + tds[1].innerHTML
            $().copyToClipboard(cp)
            $(this).parents('tr').effect('pulsate', { times: 1 }, 1000)
        })
        $('#cbkModified').on('change', function (e) {
            if (this.checked) {
                $('input[name="search"]').val('')
                $('.custom-php-settings-table tbody tr').addClass('hidden')
                $('.custom-php-settings-table tr.modified').removeClass('hidden')
            } else {
                $('.custom-php-settings-table tbody tr').removeClass('hidden')
            }
            $('.custom-php-settings-table tbody tr:not(.hidden):odd td').css({
                'background-color': '#f0f0f0',
            })
            $('.custom-php-settings-table tbody tr:not(.hidden):even td').css({
                'background-color': '#fff',
            })
        })
        $('input[name="search"]').on('keyup', function (e) {
            $('#cbkModified').prop('checked', '')
            if (e.keyCode === 13) {
                const s = this.value.toLowerCase()
                $('.custom-php-settings-table tbody tr').removeClass('hidden')
                if (!s.length) {
                    $('.custom-php-settings-table tbody tr:not(.hidden):odd td').css({
                        'background-color': '#f0f0f0',
                    })
                    $('.custom-php-settings-table tbody tr:not(.hidden):even td').css({
                        'background-color': '#fff',
                    })
                    return
                }
                const trs = $('.custom-php-settings-table tr:not(:first)')
                trs.map((k, v) => {
                    const td = $(v).find('td:first')
                    let found = $(td).text().toLowerCase().includes(s)
                    if (!found) {
                        $('.custom-php-settings-table td')
                        $(v).addClass('hidden')
                    }
                    return found
                })
                $('.custom-php-settings-table tbody tr:not(.hidden):odd td').css({
                    'background-color': '#f0f0f0',
                })
                $('.custom-php-settings-table tbody tr:not(.hidden):even td').css({
                    'background-color': '#fff',
                })
            }
        })
        // Handle dismissible notifications.
        $('.custom-php-settings-notice.notice.is-dismissible').each((a, el) => {
            $('.notice-dismiss', el).on('click', () => {
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'custom_php_settings_dismiss_notice',
                        _ajax_nonce: cps_params._ajax_nonce,
                        id: $(el).attr('id').split('-')[1],
                    },
                })
                    .done((e) => {
                        el.remove()
                    })
                    .fail((e) => {
                    })
                    .always((e) => {
                    })
            })
        })
    })
})(jQuery)
