function loadTable(){
    $(document).ready(function(){
        $('#files_Table').DataTable({
            "ajax": {
                "url": "/setup/lookup_files",                //basically tells js what url to go to in order to retrieve the desired data
                "dataType": "json",                 //format the data will be in
                "dataSrc": "data",                  //stats what the name of the src dir to look in
                "contentType": "application/json"   //pretty much the same as DataType
            },
            "columns": [
                {"data": "filename"},
                {"data": "path",
                    "fnCreatedCell": function(nTd, sData, oData, iRow, iCol){   //not sure what nTd is and could find much but it works...
                        $(nTd).html("<a target='_blank' href='/"+oData.path+""+oData.filename+"'>Click to Download</a>");
                    }
                },
                {"data": "modified"},
                {"data": "delete",
                    "fnCreatedCell": function(nTd, sData, oData, iRow, iCol){   //not sure what nTd is and could find much but it works...
                        $(nTd).html("<a href='/lookup/manage/"+oData.delete+"'>Remove</a>");
            }}
            ]
        });
    });
}
$(window).on("load", loadTable);
