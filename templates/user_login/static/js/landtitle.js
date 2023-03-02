$(document).ready(function () {

    var table


    function addLandtitle(data) {

        var settings = {
            "async": true,
            "crossDomain": true,
            "url": "landtitle",
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
            $('.modal.in').modal('hide')
            $.notify("Landtitle Added Successfully", {"status":"success"});
            table.destroy();
            $('#datatable4 tbody').empty(); // empty in case the columns change
            getLandtitle()
        });

    }

    function deleteLandtitle(land_title_no) {
        var settings = {
            "async": true,
            "crossDomain": true,
            "url": "landtitle/" + land_title_no,
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
             swal("Deleted!", "Landtitle has been deleted.", "success");
             table.destroy();
            $('#datatable4 tbody').empty(); // empty in case the columns change
            getLandtitle()
        });


       });

    }

    function updateLandtitle(data, land_title_no) {
        var settings = {
            "async": true,
            "crossDomain": true,
            "url": "landtitle/" + land_title_no,
            "method": "PUT",
            "headers": {
                "content-type": "application/json",
                "cache-control": "no-cache"
            },
            "processData": false,
            "data": JSON.stringify(data)
        }

        $.ajax(settings).done(function (response) {
            $('.modal.in').modal('hide')
            $.notify("Landtitle Updated Successfully", {"status":"success"});
            table.destroy();
            $('#datatable4 tbody').empty(); // empty in case the columns change
            getLandtitle()
        });


    }

    function getLandtitle() {

        var settings = {
            "async": true,
            "crossDomain": true,
            "url": "landtitle",
            "method": "GET",
            "headers": {
                "cache-control": "no-cache"
            }
        }

        $.ajax(settings).done(function (response) {



            table = $('#datatable4').DataTable({
                "bDestroy": true,
                'paging': true, // Table pagination
                'ordering': true, // Column ordering
                'info': true, // Bottom left status text
                aaData: response,
                "aaSorting": [],
                aoColumns: [
                {
                    mData: 'land_title_no'
                },
                {
                    mData: 'name'
                },
                {
                    mData: 'available'
                },
                {
                    mData: 'description'
                },
                {
                    mRender: function (o) {
                        return '<button class="btn-xs btn btn-info btn-edit" type="button">Edit</button>';
                    }
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
                deleteLandtitle(data.land_title_no)

            });
            $('.btn-edit').one("click", function(e) {
                var data = table.row($(this).parents('tr')).data();
                $('#myModal').modal().one('shown.bs.modal', function (e) {
                    for (var key in data) {
                        $("[name=" + key + "]").val(data[key])
                    }
                    $("#savethelandtitle").off("click").on("click", function(e) {
                        var instance = $('#detailform').parsley();
                        instance.validate()
                        console.log(instance.isValid())
                        if(instance.isValid()){
                            jsondata = $('#detailform').serializeJSON();
                            updateLandtitle(jsondata, data.land_title_no)
                        }

                    })
                })



            });

        });


    }




    $("#addLandtitle").click(function () {
        $('#detailform input,textarea').val("")
        $('#myModal').modal().one('shown.bs.modal', function (e) {

            console.log('innn')
            $("#savethelandtitle").off("click").on("click", function(e) {
                console.log("inn")
                var instance = $('#detailform').parsley();
                instance.validate()
                if(instance.isValid()){
                    jsondata = $('#detailform').serializeJSON();
                    addLandtitle(jsondata)
                }

            })

        })



    })


    getLandtitle()
})
