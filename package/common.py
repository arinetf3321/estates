from flask_restful import Resource, Api, request
from package.model import conn


class Common(Resource):
    """This contain common api ie noe related to the specific module"""

    def get(self):
        """Retrive the land, seller, appointment, caveat count for the dashboard page"""

        getLandCount=conn.execute("SELECT COUNT(*) AS land FROM land").fetchone()
        getSellerCount = conn.execute("SELECT COUNT(*) AS seller FROM seller").fetchone()
        getAppointmentCount = conn.execute("SELECT COUNT(*) AS appointment FROM appointment").fetchone()
        getCaveatCount = conn.execute("SELECT COUNT(*) AS caveat from caveat").fetchone()
        getProcedureCount = conn.execute("SELECT COUNT(*) AS procedure from procedure").fetchone()
        getLandtitleCount = conn.execute("SELECT COUNT(*) AS landtitle from landtitle").fetchone()
        getLocationCount = conn.execute("SELECT COUNT(*) AS location from location").fetchone()
        getBuyerCount = conn.execute("SELECT COUNT(*) AS buyer FROM buyer").fetchone()
        getAgreementCount = conn.execute("SELECT COUNT(*) AS agreement FROM agreement").fetchone()
        getBuy_sell_transactionCount = conn.execute("SELECT COUNT(*) AS buy_sell_transaction FROM buy_sell_transaction").fetchone()

        getLandCount.update(getSellerCount)
        getLandCount.update(getAppointmentCount)
        getLandCount.update(getCaveatCount)
        getLandCount.update(getProcedureCount)
        getLandCount.update(getLandtitleCount)
        getLandCount.update(getLocationCount)
        getLandCount.update(getBuyerCount)
        getLandCount.update(getAgreementCount)
        getLandCount.update(getBuy_sell_transactionCount)

        return getLandCount