function loadTable(){
    user_array = [];
    $(document).ready(function() {
        $.getJSON("/setup/userlist",
            function(data){
                $.each(data, function(i, field) {    //<--this .each statement doesnt really do anything
                    for (let [key, val] of Object.entries(field)) {
                        user_array.push(val.username);
                    }
                });
            }
        );

        var home_table = $('#homeTable').DataTable({
            responsive: true,
            //This function appends a 
            initComplete: function () {
                //to apply this to every column, then leave it as columns()
                //to specify which columns to apply, do columns(2,3,5)
                this.api().columns(4).every( function () {  
                    var column = this;
                    var select = $('<select><option value=""></option></select>')
                        .appendTo( $(column.footer()).empty() )
                        .on( 'change', function () {
                            var val = $.fn.dataTable.util.escapeRegex(
                                $(this).val()
                            );
                            column
                                .search( val ? '^'+val+'$' : '', true, false )
                                .draw();
                        } );
    
                    column.data().unique().sort().each( function ( d, j ) {
                        select.append( '<option value="'+d+'">'+d+'</option>' )
                    } );
                } );
            },
            "ajax": {
                "url": "/setup/home",                //basically tells js what url to go to in order to retrieve the desired data
                "dataType": "json",                 //format the data will be in
                "dataSrc": "data",                  //stats what the name of the src dir to look in
                "contentType": "application/json"   //pretty much the same as DataType
            },
            "columnDefs": [
                {"visible": false, "targets": 2}    //determines what columns to hide
            ],
            "order": [[ 2, "desc" ]],
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
                {"data": "action",
                    "fnCreatedCell": function(nTd, sData, oData, iRow, iCol){   //NOTE: fnCreatedCell only works, so renaming it breaks it. Its JS so im not suprised
                        $(nTd).html("<a href='/entry/"+oData.id+"'>"+oData.action+"</a>");
                    }
                },
                {"data": "case_id"},
                {"data": "offender_ip"},
                {"data": "date_posted"},
                {"data": "username"},
                {"data": "classification"},
                {"data": "offender_mac"}
            ]
        });

        //when a user clicks on the edit column of a row, this retrieves the data to build out the modal
        $('#homeTable tbody').on('click', 'td.edit', function () {
            //get the data for the current row
            var tr = $(this).closest('tr');
            var row = home_table.row( tr );
            var data = row.data();

            //build the modal
            $('.modal-body').html(lets_gooooooo(data));
            //show off them goods
            $('#editModal').modal({show:true});

        });
    });

    //builds out the modal in a dynamic~ish fashion
    function lets_gooooooo(data){
        //return the formated modal
        //damn this is so ugly
        var action_val;
        action_val = '<option>GENERAL</option>'+
            '<option>SPAMMING</option>'+
            '<option selected>DMCA</option>'+
            '<option>VIRUS</option>'+
            '<option>SCANNING</option>'+
            '<option>ROGUE</option>'+
            '<option>TROJAN</option>'+
            '<option>SSH</option>'+
            '<option>BADLOGINS</option>'+
            '<option>WEBVULN</option>';

        var assigned_user_val;
        if (data.action == "PENDING") {
            assigned_user_val = '<div class="form-group">'+
                                '<label for="assigned_user">Assigned to:</label>'+
                                '<select class="form-control" name="assigned_user" id="assigned_user">';
                                var counter;
                                for (counter = 0; counter <= user_array.length; counter++) {
                                    if (data.username == user_array[counter]) {
                                        assigned_user_val += '<option selected value="'+user_array[counter]+'">'+user_array[counter]+'</option>';
                                    } else {
                                        assigned_user_val += '<option value="'+user_array[counter]+'">'+user_array[counter]+'</option>';
                                    }
                                }
                                assigned_user_val += '</select>'+
                                                    '</div>';
                                assigned_user_val += '<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">'+
                                    '<tr>'+
                                        '<td>Date Blocked:</td>'+
                                        '<td>'+data.date_posted+'</td>'+
                                    '</tr>'+
                                '</table>';
        } else {
            assigned_user_val = '<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">'+
                                    '<tr>'+
                                        '<td>Blocked by:</td>'+
                                        '<td>'+data.username+'</td>'+
                                    '</tr>'+
                                    '<tr>'+
                                        '<td>Date Blocked:</td>'+
                                        '<td>'+data.date_posted+'</td>'+
                                    '</tr>'+
                                '</table>';
        }

        return '<form action="/entry/update/'+data.id+'" method="POST">'+
            '<div class="form-group">'+
                '<label for="entry_string">Offender IP:</label>'+
                '<input type="text" class="form-control" name="off_ip" id="off_ip" required value="'+data.offender_ip+'">'+
            '</div>'+
            '<div class="form-group">'+
                '<label for="entry_string">Offender MAC:</label>'+
                '<input type="text" class="form-control" name="off_mac" id="off_mac" required value="'+data.offender_mac+'">'+
            '</div>'+
            '<div class="form-group">'+
                '<label for="entry_string">Status:</label>'+
                '<input type="text" class="form-control" name="action" id="action" required value="'+data.action+'">'+
            '</div>'+
            '<div class="form-group">'+
                '<label for="entry_string">Case ID:</label>'+
                '<input type="text" class="form-control" name="case_id" id="case_id" required value="'+data.case_id+'">'+
            '</div>'+
            '<div class="form-group">'+
                '<label for="classification">Classification:</label>'+
                '<select class="form-control" name="classification" id="classification">'+
                    action_val+
                '</select>'+
            '</div>'+
            '<div class="form-group">'+
                '<label for="evidence">Evidence:</label>'+
                '<textarea class="form-control" rows="5" name="evidence" id="evidence">'+ data.evidence +'</textarea>'+
            '</div>'+
            assigned_user_val+
            '<div class="modal-footer">'+
                //setup a button to remove the current entry
                '<input class="btn btn-primary" type="submit" value="Update">'+
                '<button class="btn btn-danger" type="submit" formaction="/entry/'+data.id+'/delete">Remove Entry</button>'+
                '<button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>'+
            '</div>'+
        '</form>';
    }
}
$(window).on("load", loadTable);



function loadLinks(){
    $(document).ready(function(){
        //get a json result from the link provided
        $.getJSON("/link_data",
            function(data){
                $.each(data, function(i, field){    //<--this .each statement doesnt really do anything 
                    var j = 0;
                    //iterate through the results and assign to local variables
                    for(j = 0; j < field.length; j++){
                        var category =field[j].category;
                        var url_link = field[j].url_link;
                        var display_text = field[j].display_text;

                        //prep the var using the locals defined above
                        var linkPrep = category+" <a href="+url_link+" target='_blank'>"+display_text+"</a><br>";   //Random note: apparently the <a> tag doesnt like a trailing / on a link
                        //append it to the div with the id = links
                        $('#links').append(linkPrep);
                    }
                });   
            }
        );
    });
}
//function to query and randomly select an entry on button press
function loadFoods(){
    $(document).ready(function(){
        //below code states that we only query once we get a button click
        $('button').click(function(){
            //get a json result from the link provided
            $.getJSON("/setup/food", function(data){
                $.each(data, function(i, field){    //<--this .each statement doesnt really do anything 
                    //initialize variables and then select a random var from 0 to the length of the returned array
                    var indexLimit, randomIndex;
                    indexLimit = field.length;
                    randomIndex = Math.floor(Math.random() * indexLimit);
                    
                    //get the data we want
                    var food_type =field[randomIndex].food_type;
                    var restaurant = field[randomIndex].restaurant;

                    //prep the var using the locals defined above
                    var linkPrep = "<p>"+restaurant+" | "+food_type+"</p>";
                    //write to the div that has the class we want
                    //if we use .html() we need to make sure we are passing it in html format
                    $('#foods').html(linkPrep);
                    
                });   
            });
        });
    });
}

//call the above functions when the page loads
$(window).on("load", loadLinks);
$(window).on("load", loadFoods);
