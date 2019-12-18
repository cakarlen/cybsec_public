function loadTable() {
    $(document).ready(function () {
        var post_table = $('#UsersPostsTable').DataTable({
            "ajax": {
                "url": "/setup/pastebin",
                "dataType": "json",
                "dataSrc": "data",
                "contentType": "application/json"
            },
            "order": [[2, "desc"]],
            "columnDefs": [
                {"visible": false, "targets": 2}    //determines what columns to hide
            ],
            "columns": [
                //The below data column is just used to have the icon for child row display when data goes past the boundaries
                {
                    "className": 'details-control',
                    "orderable": false,
                    "data": null,
                    "defaultContent": ''
                },
                //used to hold the edit icon
                {
                    "className": 'edit',
                    "orderable": false,
                    "data": null,
                    "defaultContent": '<i class="fa fa-edit"></i>'  //for some reason this had to be class="fa fa-edit" and not class="far fa-edit" idk why tho...
                },
                {"data": "id"},
                {"data": "date"},
                {"data": "status"},
                {
                    "data": "comp_user",
                    "fnCreatedCell": function (nTd, sData, oData, iRow, iCol) {   //not sure what nTd is and could find much but it works...
                        $(nTd).html("<a href='/pastebin/update/" + oData.id + "'>" + oData.comp_user + "</a>");
                    }
                },
                {"data": "username"},
                {
                    "data": "remove",
                    "fnCreatedCell": function (nTd, sData, oData, iRow, iCol) {   //not sure what nTd is and could find much but it works...
                        $(nTd).html("<a href='/pastebin/delete/" + oData.id + "'>Remove</a>");
                    }
                }
            ]
        });

        //when a user clicks on the edit column of a row, this retrieves the data to build out the modal
        $('#UsersPostsTable tbody').on('click', 'td.edit', function () {
            //get the data for the current row
            var tr = $(this).closest('tr');
            var row = post_table.row(tr);
            var data = row.data();

            //build the modal
            $('.modal-body').html(lets_gooooooo(data));
            //show off them goods
            $('#editModal').modal({show: true});

        });
    });

    //builds out the modal in a dynamic~ish fashion
    function lets_gooooooo(data) {
        return '<form action="/pastebin/update/post/' + data.id + '" method="POST">' +
            '<div class="form-group">' +
            '<label for="entry_string">Compromised user:</label>' +
            '<input type="text" class="form-control" name="comp_user" id="comp_user" required value="' + data.comp_user + '">' +
            '</div>' +
            '<div class="form-group">' +
            '<label for="entry_string">Data:</label>' +
            '<input type="text" class="form-control" name="data" id="data" required value="' + data.data + '">' +
            '</div>' +
            '<div class="form-group">' +
            '<label for="entry_string">Status:</label>' +
            '<input type="text" class="form-control" name="status" id="status" required value="' + data.status + '">' +
            '</div>' +
            '<div class="form-group">' +
            '<label for="entry_string">Username:</label>' +
            '<input type="text" class="form-control" name="username" id="username" required value="' + data.username + '">' +
            '</div>'+
            '<div class="modal-footer">' +
            //setup a button to remove the current entry
            '<input class="btn btn-primary" type="submit" value="Update">' +
            '<button class="btn btn-danger" type="submit" formaction="/pastebin/delete/' + data.id + '">Remove Entry</button>' +
            '<button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>' +
            '</div>' +
            '</form>';
    }
}

$(window).on("load", loadTable);