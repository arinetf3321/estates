$(document).ready(function () {

    var table


    function addSeller(data) {

        var settings = {
            "async": true,
            "crossDomain": true,
            "url": "seller",
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
            $.notify("Seller Added Successfully", { "status": "success" });
            table.destroy();
            $('#datatable4 tbody').empty(); // empty in case the columns change
            getSeller()
        });

    }

    function deleteSeller(id) {
        var settings = {
            "async": true,
            "crossDomain": true,
            "url": "seller/" + id,
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
        }, function () {
            $.ajax(settings).done(function (response) {
                swal("Deleted!", "Seller has been deleted.", "success");
                table.destroy();
                $('#datatable4 tbody').empty(); // empty in case the columns change
                getSeller()
            });


        });

    }

    function updateSeller(data, id) {
        var settings = {
            "async": true,
            "crossDomain": true,
            "url": "seller/" + id,
            "method": "PUT",
            "headers": {
                "content-type": "application/json",
                "cache-control": "no-cache"
            },
            "processData": false,
            "data": JSON.stringify(data)
        }

        $.ajax(settings).done(function (response) {
            $.notify("Seller Updated Successfully", { "status": "success" });
            $('.modal.in').modal('hide')
            table.destroy();
            $('#datatable4 tbody').empty(); // empty in case the columns change
            getSeller()
        });


    }

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



            table = $('#datatable4').DataTable({
                "bDestroy": true,
                'paging': true, // Table pagination
                'ordering': true, // Column ordering
                'info': true, // Bottom left status text
                aaData: response,
                "aaSorting": [],
                aoColumns: [
                    {
                        mData: 'seller_id'
                    },
                    {
                        mData: 'seller_first_name'
                    },
                    {
                        mData: 'seller_last_name'
                    },
                    {
                        mData: 'seller_address'
                    },
                    {
                        mData: 'seller_ph_no'
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
                deleteSeller(data.seller_id)

            });
            $('.btn-edit').one("click", function (e) {
                var data = table.row($(this).parents('tr')).data();
                $('#myModal').modal().one('shown.bs.modal', function (e) {
                    for (var key in data) {
                        $("[name=" + key + "]").val(data[key])
                    }
                    $("#savetheland").off("click").on("click", function (e) {
                        var instance = $('#detailform').parsley();
                        instance.validate()
                        console.log(instance.isValid())
                        if (instance.isValid()) {
                            jsondata = $('#detailform').serializeJSON();
                            updateSeller(jsondata, data.seller_id)
                        }

                    })
                })



            });

        });


    }




    $("#addland").click(function () {
        $('#detailform input,textarea').val("")
        $('#myModal').modal().one('shown.bs.modal', function (e) {

            console.log("innn")
            $("#savetheland").off("click").on("click", function (e) {
                console.log("inn")
                var instance = $('#detailform').parsley();
                instance.validate()
                if (instance.isValid()) {
                    jsondata = $('#detailform').serializeJSON();
                    addSeller(jsondata)
                }

            })

        })



    })


    getSeller()
})
