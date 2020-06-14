/*
 * JavaScript file for the application to demonstrate
 * using the API
 */

// Create the namespace instance
let ns = {};

// Create the model instance
ns.model = (function () {
    'use strict';

    let $event_pump = $('body');

    // Return the API
    return {
        'read': function () {
            let ajax_options = {
                type: 'GET',
                url: 'people',
                accepts: 'application/json',
                dataType: 'json'
            };
            $.ajax(ajax_options)
                .done(function (data) {
                    $event_pump.trigger('model_read_success', [data]);
                })
                .fail(function (xhr, textStatus, errorThrown) {
                    alert('failed to load subscribers list: a valid token is required for this request');
                })
        },

        create: function (fname, email, access_token) {
            let ajax_options = {
                type: 'POST',
                url: 'people',
                accepts: 'application/json',
                contentType: 'application/json',
                dataType: 'json',
                data: JSON.stringify({
                    'fname': fname,
                    'email': email,
                    'x-access-token':access_token
                })
            };
            $.ajax(ajax_options)
                .done(function (data) {
                    $event_pump.trigger('model_create_success', [data]);
                    $('#msg').removeClass('error').addClass('success');
                    $('#msg').text(data.fname + ' added to mailing list successfully.').show();
                    setTimeout(function () {
                        $('#msg').hide();
                    }, 3000);

                })
                .fail(function (xhr, textStatus, errorThrown) {
                    $event_pump.trigger('model_error', [xhr, textStatus, errorThrown]);
                });
        },

        update: function (fname, email, access_token) {
            let ajax_options = {
                type: 'PUT',
                url: 'people/' + email,
                accepts: 'application/json',
                contentType: 'application/json',
                dataType: 'json',
                data: JSON.stringify({
                    'fname': fname,
                    'email': email,
                    'x-access-token': access_token
                })
            };
            $.ajax(ajax_options)
                .done(function (data) {
                    $event_pump.trigger('model_update_success', [data]);
                    $('#msg').removeClass('error').addClass('success');
                    $('#msg').text('Record for ' + data.fname + ' updated successfully').show();
                    setTimeout(function () {
                        $('#msg').hide();
                    }, 3000);
                })
                .fail(function (xhr, textStatus, errorThrown) {
                    $event_pump.trigger('model_error', [xhr, textStatus, errorThrown]);
                })
        },

        'delete': function (email, access_token) {
            let ajax_options = {
                type: 'DELETE',
                url: 'people/' + email,
                accepts: 'application/json',
                contentType: 'plain/text'
            };
            $.ajax(ajax_options)
                .done(function (data) {
                    $event_pump.trigger('model_delete_success', [data]);
                    $('#msg').removeClass('error').addClass('success');
                    $('#msg').text(data).show();
                    setTimeout(function () {
                        $('#msg').hide();
                    }, 3000);
                })
                .fail(function (xhr, textStatus, errorThrown) {
                    $event_pump.trigger('model_error', [xhr, textStatus, errorThrown]);
                })
        },

        'fetch_mailing_list': function () {
            let ajax_options = {
                type: 'GET',
                url: 'people',
                accepts: 'application/json',
                dataType: 'json'
            };
            $.ajax(ajax_options)
                .done(function (data) {
                    var mailing_list = [];
                    for (var i = 0; i < data.length; i++) {
                        var email = data[i].email;
                        mailing_list.push(email);
                    }
                    if (data.length > 0) {
                        // mailing_list = mailing_list.slice(1);

                        // Load the recipient fields with mail_list from API
                        $('#mail_recipients').val(mailing_list);

                        $('#mail_msg').removeClass('alert alert-danger').addClass('alert alert-info');
                        $('#mail_msg').text('Mailing list loaded successfully.').show();
                        setTimeout(function () {
                            $('#mail_msg').hide();
                        }, 3000);
                    } else {
                        $('#mail_msg').removeClass('alert alert-danger').addClass('alert alert-warning');
                        $('#mail_msg').text('Oops! mailing list is empty.').show();
                        setTimeout(function () {
                            $('#mail_msg').hide();
                        }, 4000);
                    }
                })
                .fail(function (xhr, textStatus, errorThrown) {
                    $('#mail_msg').removeClass('success').addClass('alert error');
                    $('#mail_msg').text('Oops! error fetching mailing list.').show();
                    setTimeout(function () {
                        $('#mail_msg').hide();
                    }, 4000);
                });
        },
    };
}());

// Create the view instance
ns.view = (function () {
    'use strict';

    let $fname = $('#fname'),
        $email = $('#email');

    // return the API
    return {
        reset: function () {
            $email.val('');
            $fname.val('').focus();
        },

        update_editor: function (fname, email) {
            $email.val(email);
            $fname.val(fname).focus();
        },

        build_table: function (people) {
            let rows = ''

            // clear the table
            $('.people table > tbody').empty();

            // did we get a people array?
            if (people) {
                for (let i = 0, l = people.length; i < l; i++) {
                    rows += `<tr title="Double Click to Edit"><td class="fname">${people[i].fname}</td><td class="email">${people[i].email}</td><td>` + (people[i].timestamp) + `</td></tr>`;
                }
                $('table > tbody').append(rows);
            }
        },

        error: function (error_msg) {
            $('#msg').removeClass('success').addClass('error')
            $('#msg').text(error_msg).show();
            setTimeout(function () {
                $('#msg').hide();
            }, 3000);
        }
    };
}());

// Create the controller
ns.controller = (function (m, v) {
    'use strict';

    let model = m,
        view = v,
        $event_pump = $('body'),
        $fname = $('#fname'),
        $email = $('#email'),
        $access_token = $('#access_token');

    // Get the data from the model after the controller is done initializing
    setTimeout(function () {
        model.read();
    }, 100)

    // Validate input
    function validate(fname, email) {
        return fname !== "" && email !== "";
    }

    // Create our event handlers
    $('#create').click(function (e) {
        let fname = $fname.val(),
            email = $email.val(),
            access_token = $access_token.val();

        e.preventDefault();

        if (validate(fname, email, access_token)) {
            model.create(fname, email, access_token)
        } else {
            alert('Problem with full name, email or access token input');
        }
    });

    $('#update').click(function (e) {
        let fname = $fname.val(),
            email = $email.val(),
            access_token = $access_token.val();

        e.preventDefault();

        if (validate(fname, email, access_token)) {
            model.update(fname, email, access_token)
        } else {
            alert('Problem with full name, email or access token input');
        }
        e.preventDefault();
    });

    $('#delete').click(function (e) {
        let email = $email.val();

        e.preventDefault();
        var result = confirm('Are you sure you want to delete this record?');
        if (result === true) {

            if (validate('placeholder1', 'placeholder2', email)) {
                model.delete(email)
            } else {
                alert('Problem with email input');
            }
        }

    });

    $('#reset').click(function () {
        view.reset();
    });

    $('#mail_list').click(function () {
        model.fetch_mailing_list();
    });

    $('table > tbody').on('dblclick', 'tr', function (e) {
        let $target = $(e.target),
            fname,
            email;

        fname = $target
            .parent()
            .find('td.fname')
            .text();

        email = $target
            .parent()
            .find('td.email')
            .text();

        view.update_editor(fname, email);
    });

    // Handle the model events
    $event_pump.on('model_read_success', function (e, data) {
        view.build_table(data);
        view.reset();
    });

    $event_pump.on('model_create_success', function (e, data) {
        model.read();
        view.reset();
    });

    $event_pump.on('model_update_success', function (e, data) {
        model.read();
        view.reset();
    });

    $event_pump.on('model_delete_success', function (e, data) {
        model.read();
        view.reset();
    });

    $event_pump.on('model_error', function (e, xhr, textStatus, errorThrown) {
        let error_msg = textStatus + ': ' + xhr.responseJSON.detail;
        view.error(error_msg.data.message);
        console.log(error_msg.data.message);
    })
}(ns.model, ns.view));

$(document).ready(function () {
    //Sendmail Demo form
    $('#mail_form').submit(function (event) {
        event.preventDefault();
        let subject = $('#mail_subject').val();
        let message = $('#mail_message').val();
        let recipients = $('#mail_recipients').val();
        let is_mail_template = $('#mail_template').prop('checked');
        if (!subject || !message || !recipients) {
            $('#mail_msg').removeClass('alert-alert-info');
            $('#mail_msg').removeClass('alert-alert-sucess').addClass('alert alert-danger');
            $('#mail_msg').text('All fields are required').show();
            setTimeout(function () {
                $('#mail_msg').hide();
            }, 4000);
        } else {
            $('#mail_msg').removeClass('alert-alert-danger');
            $('#mail_msg').removeClass('alert-alert-sucess').addClass('alert alert-info');
            $('#mail_msg').text('Processing...').show();

            if (is_mail_template) {
                let ajax_options = {
                    type: 'POST',
                    url: '/sendmail/html',
                    data: { 'subject': subject, 'message': message, 'recipients': recipients },
                    accepts: 'application/json',
                    dataType: 'json'
                };
                $.ajax(ajax_options).done(function (res) {
                    $('#mail_form')[0].reset();
                    $('#mail_msg').removeClass('alert alert-info');
                    $('#mail_msg').removeClass('alert alert-danger').addClass('alert alert-success');
                    $('#mail_msg').text(res.data.message).show();
                    setTimeout(function () {
                        $('#mail_msg').hide();
                    }, 4000);
                }).fail(function (res) {
                    $('#mail_msg').removeClass('alert-alert-info');
                    $('#mail_msg').removeClass('alert-alert-sucess').addClass('alert alert-danger');
                    $('#mail_msg').text(res.data.message).show();
                    setTimeout(function () {
                        $('#mail_msg').hide();
                    }, 4000);

                });
            } else {
                let ajax_options = {
                    type: 'POST',
                    url: '/sendmail/text',
                    data: { 'subject': subject, 'message': message, 'recipients': recipients },
                    accepts: 'application/json',
                    dataType: 'json'
                };
                $.ajax(ajax_options).done(function (res) {
                    $('#mail_form')[0].reset();
                    $('#mail_msg').removeClass('alert alert-info');
                    $('#mail_msg').removeClass('alert alert-danger').addClass('alert alert-success');
                    $('#mail_msg').text(res.data.message).show();
                    setTimeout(function () {
                        $('#mail_msg').hide();
                    }, 4000);
                }).fail(function (res) {
                    $('#mail_msg').removeClass('alert alert-info');
                    $('#mail_msg').removeClass('alert alert-success').addClass('alert alert-danger');
                    $('#mail_msg').text(res.data.message).show();
                    setTimeout(function () {
                        $('#mail_msg').hide();
                    }, 4000);

                });
            }
        }

    });
});
