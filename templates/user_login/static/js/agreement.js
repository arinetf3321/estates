$(document).ready(function () {

    var table

    function addAgreement(data) {

        var settings = {
            "async": true,
            "crossDomain": true,
            "url": "agreement",
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
            $.notify("Agreement Added Successfully", {"status":"success"});
            table.destroy();
            $('#datatable4 tbody').empty(); // empty in case the columns change
            getAgreement()
        });

    }

    function getAgreement() {

        var settings = {
            "async": true,
            "crossDomain": true,
            "url": "agreement",
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
                    mData: 'agreement_code'
                },
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
                    mData: 'land_id'
                },
                {
                    mData: 'landowner_first_name'
                },
                {
                    mData: 'landowner_last_name'
                },
                {
                    mData: 'buy_code'
                },
                {
                    mData: 'number'
                }
                ]
            });
            $('#datatable4 tbody').on('click', '.delete-btn', function () {
                var data = table.row($(this).parents('tr')).data();
                console.log(data)
                deleteAgreement(data.agreement_code)

            });
            $('.btn-edit').one("click", function(e) {
                var data = table.row($(this).lands('tr')).data();
                $('#myModal').modal().one('shown.bs.modal', function (e) {
                    for (var key in data) {
                        $("[name=" + key + "]").val(data[key])
                    }
                    $("#savetheagreement").off("click").on("click", function(e) {
                        var instance = $('#detailform').parsley();
                        instance.validate()
                        console.log(instance.isValid())
                        if(instance.isValid()){
                            jsondata = $('#detailform').serializeJSON();
                            updateAgreement(jsondata, data.agreement_code)
                        }

                    })
                })



            });

        });


    }




    $("#addAgreement").click(function () {
        $('#detailform input,textarea').val("")
        $('#myModal').modal().one('shown.bs.modal', function (e) {

            $(".form_datetime").datetimepicker({
             format: 'yyyy-mm-dd hh:ii:ss',
             startDate:new Date(),
             initialDate: new Date()
            });
            console.log("innn")
            $("#savetheagreement").off("click").on("click", function(e) {
                console.log("inn")
                var instance = $('#detailform').parsley();
                instance.validate()
                if(instance.isValid()){
                    jsondata = $('#detailform').serializeJSON();
                    addAgreement(jsondata)
                }

            })

        })

    })


    getAgreement()
})
