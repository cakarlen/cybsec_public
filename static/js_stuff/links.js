function loadTable(){
    $(document).ready(function(){
        $('#links_Table').DataTable({
            //This function appends a 
            initComplete: function () {
                //to apply this to every column, then leave it as columns()
                //to specify which columns to apply, do columns(2,3,5)
                this.api().columns().every( function () {  
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
                "url": "/link_data",                //basically tells js what url to go to in order to retrieve the desired data
                "dataType": "json",                 //format the data will be in
                "dataSrc": "data",                  //stats what the name of the src dir to look in
                "contentType": "application/json"   //pretty much the same as DataType
            },
            "columnDefs": [
                {"visible": false, "targets": 0}    //determines what columns to hide
            ],
            "columns": [
                {"data": "id"},
                {"data": "url_link"},
                {"data": "display_text"},
                {"data": "category"},
                {"data": "remove",
                    "fnCreatedCell": function(nTd, sData, oData, iRow, iCol){   //not sure what nTd is and could find much but it works...
                        $(nTd).html("<a href='/link/remove/"+oData.id+"'>Remove</a>");
                }
                }
            ]
        });
});

}
$(window).on("load", loadTable);
