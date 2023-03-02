$(document).ready(function () {

  var settings = {
    "async": true,
    "crossDomain": true,
    "url": "common",
    "method": "GET",
    "headers": {
      "cache-control": "no-cache"
    }
  }

  $.ajax(settings).done(function (response) {
    console.log(response);
    $('#landcount').text(response.land)
    $('#sellercount').text(response.seller)
    $('#appointmentcount').text(response.appointment)
    $('#caveatcount').text(response.caveat)
    $('#locationcount').text(response.location)
    $('#buyercount').text(response.buyer)
    $('#landtitlecount').text(response.landtitle)
    $('#buy_procedurecount').text(response.buy_procedure)
    $('#agreementcount').text(response.agreement)
    $('#buy_sell_transactioncount').text(response.buy_sell_transaction)
  });


})
