function loadTable(){
    $(document).ready(function(){
        var colGroup = 6;
        var ip_table = $('#edl_IP_TableTest').DataTable({
            responsive: true,                       //enables the responsive capabilities
            
            //the ajax section basically denotes what and where the data is
            "ajax": {
                "url": "/edl_data",                 //basically tells js what url to go to in order to retrieve the desired data
                "dataType": "json",                 //format the data will be in
                "dataSrc": "ip",                    //stats what the name of the src dir to look in
                "contentType": "application/json"   //pretty much the same as DataType
            },
            //denotes the order of the row length section
            "lengthMenu": [[100, 50, 25, 10, -1], [100, 50, 25, 10, "ALL"]],
            //where we define what data the table should expect. NOTE: Must be in order
            "columns": [
                //The below data column is just used to have the icon for child row display when data goes past the boundaries 
                {
                    "className":      'details-control',
                    "orderable":      false,
                    "data":           null,
                    "defaultContent": '' 
                },
                //used to hold the edit icon
                {
                    "className":      'edit',
                    "orderable":      false,
                    "data":           null,
                    "defaultContent": '<i class="fa fa-edit"></i>'  //for some reason this had to be class="fa fa-edit" and not class="far fa-edit" idk why tho...
                },
                {"data": "id"},
                {"data": "ip_string"},
                {"data": "comments"},
                {"data": "username"},
                {"data": "status"},
                {"data": "direction_block"},
                {"data": "date_blocked"},
                {"data": "date_allowed"}
            ],
            //more control on columns
            "columnDefs": [
                {"visible": false, "targets": 2, colGroup},    //determines what columns to hide
                //the render below was used for testing stuff but things got more complicated and time consumming than it was worth
                //the initial goal was to have a selected column's text wrap to the next line
                /*
                {render: function (data, type, full, meta) {
                        return "<div class='text-wrap width-200'>" + data + "</div>";
                    },
                targets: 4},*/
            ],
            //just for future ref. each char the dom string below denotes the element to place and in what order
            //ref: https://datatables.net/examples/basic_init/dom.html
            dom: 'lBfrtip',
            buttons: [
                'colvis'
            ],
            //reference link: https://datatables.net/examples/advanced_init/row_grouping.html
            'order':  [[colGroup, 'asc']],
            'drawCallback':   function(settings){
                var api = this.api();
                var rows = api.rows( {page: 'current'} ).nodes();
                var last = null;

                //tbh, I kinda just copy pasted and hoped for the best
                //but i believe it is detemining if the next row is in the same group as the current element
                //if it is then dont make another group label, otherwise make another group label
                api.column(colGroup, {page: 'current'} ).data().each( function(group, i){
                    if(last !== group){
                        $(rows).eq(i).before(
                            '<tr class="group"><td colspan="5">'+group+'</td></tr>'
                        );
                        last = group;
                    }
                });
            }
        });
        var edl_table = $('#edl_URL_TableTest').DataTable({
            responsive: true,
            "ajax": {
                "url": "/edl_data",                //basically tells js what url to go to in order to retrieve the desired data
                "dataType": "json",                 //format the data will be in
                "dataSrc": "url",                  //stats what the name of the src dir to look in
                "contentType": "application/json"   //pretty much the same as DataType
            },
            "columnDefs": [
                {"visible": false, "targets": 2, colGroup}    //determines what columns to hide
            ],
            "lengthMenu": [[100, 50, 25, 10, -1], [100, 50, 25, 10, "ALL"]],
            "columns": [
                {
                    "className":      'details-control',
                    "orderable":      false,
                    "data":           null,
                    "defaultContent": '' 
                },
                {
                    "className":      'edit',
                    "orderable":      false,
                    "data":           null,
                    "defaultContent": '<i class="fa fa-edit"></i>'  //for some reason this had to be class="fa fa-edit" and not class="far fa-edit" idk why tho...
                },
                {"data": "id"},
                {"data": "url_string"},
                {"data": "comments"},
                {"data": "username"},
                {"data": "status"},
                {"data": "direction_block"},
                {"data": "date_blocked"},
                {"data": "date_allowed"}
            ],
            //just for future ref. each char the dom string below denotes the element to place and in what order
            //ref: https://datatables.net/examples/basic_init/dom.html
            dom: 'lBfrtip',
            buttons: [
                'colvis'
            ],
            //reference link: https://datatables.net/examples/advanced_init/row_grouping.html
            'order':  [[colGroup, 'asc']],  //default order
            'drawCallback':   function(settings){
                var api = this.api();
                var rows = api.rows( {page: 'current'} ).nodes();
                var last = null;

                //tbh, I kinda just copy pasted and hoped for the best
                //but i believe it is detemining if the next row is in the same group as the current element
                //if it is then dont make another group label, otherwise make another group label
                api.column(colGroup, {page: 'current'} ).data().each( function(group, i){
                    if(last !== group){
                        $(rows).eq(i).before(
                            '<tr class="group"><td colspan="5">'+group+'</td></tr>'
                        );
                        last = group;
                    }
                });
            }
        });

        //this section controls the tab visibility switching (i didnt really learn how this fully works shhh)
        $('a[data-toggle="tab"]').on('shown.bs.tab', function(e){
            $($.fn.dataTable.tables(true)).DataTable().responsive.recalc().columns.adjust();
        });

        //when a user clicks on the edit column of a row, this retrieves the data to build out the modal
        $('#edl_IP_TableTest tbody').on('click', 'td.edit', function () {
            //get the data for the current row
            var tr = $(this).closest('tr');
            var row = ip_table.row( tr );
            var data = row.data();

            //build the modal
            $('.modal-body').html(lets_gooooooo(data));
            //show off them goods
            $('#editModal').modal({show:true});

        });

        $('#edl_URL_TableTest tbody').on('click', 'td.edit', function () {
            //get the data for the current row
            var tr = $(this).closest('tr');
            var row = edl_table.row( tr );
            var data = row.data();
            
            //build the modal
            $('.modal-body').html(lets_gooooooo(data));
            //show off them goods
            $('#editModal').modal({show:true});

        });

        //order by grouping
        $('#edl_IP_TableTest tbody').on('click', 'tr.group', function () {
            var currOrder = ip_table.order()[0];
            if(currOrder[0] === colGroup && currOrder[1] === 'asc'){
                ip_table.order([colGroup, 'desc']).draw();
            }
            else{
                ip_table.order([colGroup, 'asc']).draw();
            }
        });

        //order by grouping
        $('#edl_URL_TableTest tbody').on('click', 'tr.group', function () {
            var currOrder = edl_table.order()[0];
            if(currOrder[0] === colGroup && currOrder[1] === 'asc'){
                edl_table.order([colGroup, 'desc']).draw();
            }
            else{
                edl_table.order([colGroup, 'asc']).draw();
            }
        });
    });
    
    //builds out the modal in a dynamic~ish fashion
    function lets_gooooooo(data){
        //data is gonna ref the stuff from the currently selected row             
        var edl_table;
        var entry_string_val;
        
        var passed_data = '<input type="hidden" name="edl_entryid" value='+data.id+'>';

        //checks if data contains a key called ip_string
        if (typeof data.ip_string !== "undefined"){
            edl_table = 'ip';
            entry_string_val = data.ip_string;
        }
        else{
            edl_table = 'url';
            entry_string_val = data.url_string;
            input_attr = '';
        }

        passed_data = passed_data + '<input type="hidden" name="edl_table" value='+edl_table+'>';

        //select the default value based on current data 
        //prob a better way to do this but oh wellllll
        var dir_block_val;
        if(data.direction_block == "both"){
            dir_block_val = '<option value="both" selected>Both</option>'+
            '<option value="inbound">Inbound</option>'+
            '<option value="outbound">Outbound</option>';
        }
        else if(data.direction_block == "inbound"){
            dir_block_val = '<option value="both">Both</option>'+
            '<option value="inbound" selected>Inbound</option>'+
            '<option value="outbound">Outbound</option>';
        }
        else{
            dir_block_val = '<option value="both">Both</option>'+
            '<option value="inbound">Inbound</option>'+
            '<option value="outbound" selected>Outbound</option>';
        }
        
        //set the default block status
        var status_val;
        if(data.status == "Blocked"){
            status_val = '<option value="Blocked" selected>Blocked</option>'+
            '<option value="Allowed">Allowed</option>';
        }
        else{
            status_val = '<option value="Blocked">Blocked</option>'+
            '<option value="Allowed" selected>Allowed</option>';
        }

        //return the formated modal
        //damn this is so ugly
        return '<form action="/edl/update" method="POST">'+
            '<div class="form-group">'+
                passed_data+
                '<label for="entry_string">Entry:</label>'+
                '<input type="text" class="form-control" name="entry_string" id="entry_string" required value="'+entry_string_val+'">'+
            '</div>'+
            '<div class="form-group">'+
                '<label for="comments">Comments:</label>'+
                '<textarea class="form-control" rows="2" name="comments" id="comments">'+ data.comments +'</textarea>'+
            '</div>'+
            '<div class="form-group">'+
                '<label for="status">Status:</label>'+
                '<select class="form-control" name="status" id="status">'+
                    status_val+
                '</select>'+
            '</div>'+
            '<div class="form-group">'+
                '<label for="direction_blocked">Status:</label>'+
                '<select class="form-control" name="direction_blocked" id="direction_blocked">'+
                    dir_block_val+
                '</select>'+
            '</div>'+
            '<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">'+
                '<tr>'+
                    '<td>Blocked by:</td>'+
                    '<td>'+data.username+'</td>'+
                '</tr>'+
                '<tr>'+
                    '<td>Date Blocked:</td>'+
                    '<td>'+data.date_blocked+'</td>'+
                '</tr>'+
                '<tr>'+
                    '<td>Date Unblocked:</td>'+
                    '<td>'+data.date_allowed+'</td>'+
                '</tr>'+
            '</table>'+
            '<div class="modal-footer">'+
                //setup a button to remove the current entry
                '<button class="btn btn-danger" type="submit" value="remove" formaction="/edl/remove">Remove Entry</button>'+
                '<button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>'+
                    '<input class="btn btn-primary" type="submit" value="Update">'+
            '</div>'+
        '</form>';
    }
}
$(window).on("load", loadTable);