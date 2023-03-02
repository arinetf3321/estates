$(document).ready(function () {

    var table


    function addAppointment(data) {

        var settings = {
            "async": true,
            "crossDomain": true,
            "url": "appointment",
            "method": "POST",
            "headers": {
                "content-type": "application/json",
                "cache-control": "no-cache",
                "postman-token": "2612534b-9ccd-ab7e-1f73-659029967199"
            },
            "processData": false,
            "data": JSON.stringify(data)
        }

        $.ajax(settings).done(function (response) {
           $.notify("Appointment Added Successfully", {"status":"success"});

           $('.modal.in').modal('hide')
           table.destroy();
            $('#datatable4 tbody').empty(); // empty in case the columns change
            getAppointment()
        });

    }

    function deleteAppointment(app_id) {
        var settings = {
            "async": true,
            "crossDomain": true,
            "url": "appointment/" + app_id,
            "method": "DELETE",
            "headers": {
                "cache-control": "no-cache",
                "postman-token": "28ea8360-5af0-1d11-e595-485a109760f2"
            }
        }

        swal({
            title: "Are you sure?",
            text: "You will not be able to recover this data",
            type: "warning",
            showCancelButton: true,
            confirmButtonColor: "#DD6B55",
            confirmButtonText: "Yes, delete it!",
            closeOnConfirm: false
        }, function() {
           $.ajax(settings).done(function (response) {
             swal("Deleted!", "Appointment has been deleted.", "success");
             table.destroy();
            $('#datatable4 tbody').empty(); // empty in case the columns change
            getAppointment()
        });


       });

    }



    function getAppointment() {

        var settings = {
            "async": true,
            "crossDomain": true,
            "url": "appointment",
            "method": "GET",
            "headers": {
                "cache-control": "no-cache"
            }
        }

        $.ajax(settings).done(function (response) {

            for(i=0;i<response.length;i++){
                response[i].landowner_fullname=response[i].landowner_first_name+" "+response[i].landowner_last_name
                response[i].seller_fullname=response[i].seller_first_name+" "+response[i].seller_last_name
            }



            table = $('#datatable4').DataTable({
                "bDestroy": true,
                'paging': true, // Table pagination
                'ordering': true, // Column ordering
                'info': true, // Bottom left status text
                aaData: response,
                "aaSorting": [],
                aoColumns: [
                {
                    mData: 'seller_fullname'
                },
                {
                    mData: 'landowner_fullname'
                },
                {
                    mData: 'appointment_date'
                },
                {
                    mRender: function (o) {
                        return '<button class="btn-xs btn btn-danger delete-btn" type="button">Delete</button>';
                    }
                }
                ]
            });
            $('#datatable4 tbody').on('click', '.delete-btn', function () {
                var data = table.row($(this).parents('tr')).data();
                console.log(data)
                deleteAppointment(data.app_id)

            });


        });


    }




    $("#addland").click(function () {
        $('#detailform input,textarea').val("")
        $('#myModal').modal().one('shown.bs.modal', function (e) {

            $("#seller_select").html(sellerSelect)
            $("#land_select").html(landSelect)

            $(".form_datetime").datetimepicker({
               format: 'yyyy-mm-dd hh:ii:ss',
               startDate:new Date(),
               initialDate: new Date()
           });
            console.log("innn")
            $("#savetheland").off("click").on("click", function(e) {
                console.log("inn")
                var instance = $('#detailform').parsley();
                instance.validate()
                if(instance.isValid()){
                    jsondata = $('#detailform').serializeJSON();
                    addAppointment(jsondata)
                }

            })

        })



    })


    var sellerSelect=""
    function getSeller() {

        var settings = {
            "async": true,
            "crossDomain": true,
            "url": "seller",
            "method": "GET",
            "headers": {
                "cache-control": "no-cache"
            }
        }

        $.ajax(settings).done(function (response) {

            for(i=0;i<response.length;i++){

                response[i].seller_fullname=response[i].seller_first_name+" "+response[i].seller_last_name
                sellerSelect +="<option value="+response[i].seller_id+">"+response[i].seller_fullname+"</option>"
            }


        })
    }
    var landSelect=""
    function getLand() {

        var settings = {
            "async": true,
            "crossDomain": true,
            "url": "land",
            "method": "GET",
            "headers": {
                "cache-control": "no-cache"
            }
        }

        $.ajax(settings).done(function (response) {
           for(i=0;i<response.length;i++){
              response[i].landowner_fullname=response[i].landowner_first_name+" "+response[i].landowner_last_name
              landSelect +="<option value="+response[i].land_id+">"+response[i].landowner_fullname+"</option>"
          }

      })
    }

    getSeller()
    getLand()
    getAppointment()
})