function loadTable(){
    $(document).ready(function(){
        var dt = $('#dmcaTable').DataTable({
            initComplete: function () {
                //to apply this to every column, then leave it as columns()
                //to specify which columns to apply, do columns(2,3,5)
                this.api().columns(5).every( function () {  
                    var column = this;
                    var select = $('<select><option value=""></option></select>')
                        .appendTo( $(column.header()).empty() )
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
            //testing modal stuff
            responsive: {
                details: {
                    display: $.fn.dataTable.Responsive.display.modal( {
                        //so this function is purely just for the header
                        header: function ( row ) {
                            //data contains the values in the same way as a python dict
                            //this is optional
                            var data = row.data();
                            if (data.action == "BLOCKED"){
                                return 'Details for '+data.case_id+'. <br><a class="btn btn-danger"  href="/entry/'+data.id+'">Edit/Unblock</a>';
                            }
                            else{
                                return 'Details for '+data.case_id+'. <br><a class="btn btn-danger"  href="/entry/'+data.id+'">Edit</a>';
                            }
                            
                        }
                    } ),
                    //this is what actually renders all the contents as a table
                    //normally would just show what was hidden
                    renderer: $.fn.dataTable.Responsive.renderer.tableAll( {
                        tableClass: 'table'
                    } )
                }
            },
            
            //adds a child row to auto hide long text columns                            
            "ajax": {
                "url": "/dmca/data",                //basically tells js what url to go to in order to retrieve the desired data
                "dataType": "json",                 //format the data will be in
                "dataSrc": "data",                  //stats what the name of the src dir to look in
                "contentType": "application/json"   //pretty much the same as DataType
            },
            "columnDefs": [{
                className: 'control',
                orderable: false,
                targets: 0},                         //this col is used to show the child rows when clicked 
                {"visible": false, "targets": 1},    //determines what columns to hide
                {targets: 3, render: function(data){
                        return moment(data).format('LLL');
                }}
            ],
            "columns": [
                {
                    "class":          "details-control",
                    "orderable":      false,
                    "data":           null,
                    "defaultContent": ""
                },
                {"data": "id"},
                {"data": "case_id"},
                {"data": "date_posted"},
                {"data": "username"},
                {"data": "action"},                    
                {"data": "classification"},
                {"data": "offender_ip"},
                {"data": "offender_mac"}
            ]
        });
    });
}
$(window).on("load", loadTable);
