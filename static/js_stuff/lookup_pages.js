function loadTable(){
    $(document).ready(function(){
        
        //when the page loads, get the page list and create multiple nav tabs and tables with 
        //thier respective columns
        //NOTE: make sure that the first tab has the active attribute
        
        $.getJSON("/setup/lookup/list",
            function(data){
                $.each(data, function(i, field){    //<--this .each statement doesnt really do anything 
                    couch_flag = true;  //dont question my naming conventions. I know they are horrible
                    for (let [key, val] of Object.entries(field)){
                        //console.log(key, val);

                        var keyClean = key.slice(0, -4)

                        //start creating the table basics and navs
                        var navs;
                        var fresh_table;

                        //determine if this is the first tab we are doing since we need one to be active
                        //key will hold the string val of the current table name
                        if (couch_flag == true){
                            navs = navTab_bonk(keyClean, 'active');
                            //build the table 
                            fresh_table = table_bake(keyClean, val, 'active');
                            couch_flag = false; //set flag to false
                        }
                        else{
                            navs = navTab_bonk(keyClean, '');    //send empty string
                            fresh_table = table_bake(keyClean, val);
                        }

                        

                        //add the elements to the respective divs
                        $("#navTabDiv").append(navs);
                        $("#tableDiv").append(fresh_table);

                        var testKey = '#'+keyClean;     //set the table id var
                        
                        //create the ajax config
                        var ajaxConfig = {
                            url: '/setup/lookup/list/'+String(key),
                            dataType: "json",
                            dataSrc: keyClean,
                            contentType: "application/json"
                        }

                        //create the columns config
                        var columnsConfig = []
                        for (i in val){
                            columnsConfig = columnsConfig.concat({data: String(val[i])});
                            //console.log(val[i]);
                        }

                        //create the datatable
                        $(testKey).DataTable({
                            responsive: true,
                            ajax: ajaxConfig,
                            columns: columnsConfig
                        })
                    }
                });
            }
        );
        //this section controls the tab visibility switching (i didnt really learn how this fully works shhh)
        $('a[data-toggle="tab"]').on('shown.bs.tab', function(e){
            $($.fn.dataTable.tables(true)).DataTable().responsive.recalc().columns.adjust();
        });
        
        

        //create the inner navigation tabs for each table
        function navTab_bonk(table_name, couch){
            return '<li class="nav-item"> '+
                '<a class="nav-link '+couch+'" href="#'+table_name+'Tab" data-toggle="tab">'+table_name+'</a>'+
            '</li>';
        }
            
        //create the table outline with the required columns added to it
        function table_bake(table_name, columns, couch){
            var col_template = '';
            for (i in columns){
                col_template += '<th>'+columns[i]+'</th>';
            }

            return '<div class="container tab-pane '+couch+' table-responsive" id="'+table_name+'Tab">'+
                '<table id="'+table_name+'" class="table table-striped table-bordered dt-responsive responsive" cellspacing="0" width="100%">'+
                    '<thead>'+
                        '<tr>'+
                            col_template+
                        '</tr>'+
                    '</thead>'+
                '</table>'+
            '</div>';

        }
    });
    }
$(window).on("load", loadTable);
