$(document).ready(function () {

    var table

    function addProjects(data) {

        var settings = {
            "async": true,
            "crossDomain": true,
            "url": "projects",
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
            $.notify("Projects Added Successfully", { "status": "success" });
            table.destroy();
            $('#datatable4 tbody').empty(); // empty in case the columns change
            getProjects()
        });

    }

    function getProjects() {

        var settings = {
            "async": true,
            "crossDomain": true,
            "url": "projects",
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
                        mData: 'project_owner'
                    },
                    {
                        mData: 'project_owner_first_name'
                    },
                    {
                        mData: 'project_owner_last_name'
                    },
                    {
                        mData: 'project_id'
                    },
                    {
                        mData: 'project_address1'
                    },
                    {
                        mData: 'project_address2'
                    },
                    {
                        mData: 'project_name'
                    },
                    {
                        mData: 'acquired_date'
                    },
                    {
                        mData: 'project_location'
                    },
                    {
                        mData: 'project_location_name1'
                    },
                    {
                        mData: 'project_location_name2'
                    },
                    {
                        mData: 'cost'
                    }
                ]
            });
            $('#datatable4 tbody').on('click', '.delete-btn', function () {
                var data = table.row($(this).parents('tr')).data();
                console.log(data)
                deleteProjects(data.project_id)

            });
            $('.btn-edit').one("click", function (e) {
                var data = table.row($(this).parents('tr')).data();
                $('#myModal').modal().one('shown.bs.modal', function (e) {
                    for (var key in data) {
                        $("[name=" + key + "]").val(data[key])
                    }
                    $("#savetheprojects").off("click").on("click", function (e) {
                        var instance = $('#detailform').parsley();
                        instance.validate()
                        console.log(instance.isValid())
                        if (instance.isValid()) {
                            jsondata = $('#detailform').serializeJSON();
                            updateProjects(jsondata, data.project_id)
                        }

                    })
                })



            });

        });


    }




    $("#addProjects").click(function () {
        $('#detailform input,textarea').val("")
        $('#myModal').modal().one('shown.bs.modal', function (e) {

            $(".form_datetime").datetimepicker({
                format: 'yyyy-mm-dd hh:ii:ss',
                startDate: new Date(),
                initialDate: new Date()
            });
            console.log("innn")
            $("#savetheprojects").off("click").on("click", function (e) {
                console.log("inn")
                var instance = $('#detailform').parsley();
                instance.validate()
                if (instance.isValid()) {
                    jsondata = $('#detailform').serializeJSON();
                    addProjects(jsondata)
                }

            })

        })

    })


    getProjects()
})
