function loadTable(){
    $(document).ready(function(){
        $('#ipamTable').DataTable({
            responsive:     true,
            scrollY:        '700px',
            scrollX:        true,
            scrollCollapse: true,
            fixedColumns:   true,
            "ajax": {
                "url": "/setup/ipam",                //basically tells js what url to go to in order to retrieve the desired data
                "dataType": "json",                 //format the data will be in
                "dataSrc": "data",                  //stats what the name of the src dir to look in
                "contentType": "application/json"   //pretty much the same as DataType
            },
            
            "lengthMenu": [[100, 50, 25, 10], [100, 50, 25, 10]],
            "columns": [
                {"data": "address*"},
                {"data": "netmask*"},
                {"data": "comment"},
                {"data": "dhcp_members"},
                {"data": "disabled"},
                {"data": "domain_name"},
                {"data": "routers"},
            ]
        });
    });
}
$(window).on("load", loadTable);
