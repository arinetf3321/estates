$(document).ready(function () {

    var table

    function addBuy_sell_transaction(data) {

        var settings = {
            "async": true,
            "crossDomain": true,
            "url": "buy_sell_transaction",
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
            $.notify("Buy_sell_transaction Added Successfully", { "status": "success" });
            table.destroy();
            $('#datatable4 tbody').empty(); // empty in case the columns change
            getBuy_sell_transaction()
        });

    }

    function getBuy_sell_transaction() {

        var settings = {
            "async": true,
            "crossDomain": true,
            "url": "buy_sell_transaction",
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
                        mData: 'land_id'
                    },
                    {
                        mData: 'buy_code'
                    },
                    {
                        mData: 'buy_date'
                    },
                    {
                        mData: 'seller_id'
                    },
                    {
                        mData: 'buyer_id'
                    },
                    {
                        mData: 'land_title_no'
                    }
                ]
            });
            $('#datatable4 tbody').on('click', '.delete-btn', function () {
                var data = table.row($(this).parents('tr')).data();
                console.log(data)
                deleteBuy_sell_transaction(data.land_id)

            });
            $('.btn-edit').one("click", function (e) {
                var data = table.row($(this).parents('tr')).data();
                $('#myModal').modal().one('shown.bs.modal', function (e) {
                    for (var key in data) {
                        $("[name=" + key + "]").val(data[key])
                    }
                    $("#savethebuy_sell_transaction").off("click").on("click", function (e) {
                        var instance = $('#detailform').parsley();
                        instance.validate()
                        console.log(instance.isValid())
                        if (instance.isValid()) {
                            jsondata = $('#detailform').serializeJSON();
                            updateBuy_sell_transaction(jsondata, data.land_id)
                        }

                    })
                })



            });

        });


    }




    $("#addBuy_sell_transaction").click(function () {
        $('#detailform input,textarea').val("")
        $('#myModal').modal().one('shown.bs.modal', function (e) {

            $(".form_datetime").datetimepicker({
                format: 'yyyy-mm-dd hh:ii:ss',
                startDate: new Date(),
                initialDate: new Date()
            });
            console.log("innn")
            $("#savethebuy_sell_transaction").off("click").on("click", function (e) {
                console.log("inn")
                var instance = $('#detailform').parsley();
                instance.validate()
                if (instance.isValid()) {
                    jsondata = $('#detailform').serializeJSON();
                    addBuy_sell_transaction(jsondata)
                }

            })

        })

    })


    getBuy_sell_transaction()
})
