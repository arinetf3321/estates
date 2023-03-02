from flask_restful import Resource, Api, request
from package.model import conn



class Agreements(Resource):
    """This contain apis to carry out activity with all agreements"""

    def get(self):
        """Retrive all the agreement and return in form of json"""

        # agreement = conn.execute("SELECT * from agreement").fetchall()
        agreement = conn.execute("SELECT agreement.seller_id, seller.seller_first_name, seller.seller_last_name, agreement.land_id, land.landowner_first_name, land.landowner_last_name, agreement.agreement_code, agreement.buy_code, agreement.number FROM agreement INNER JOIN seller ON agreement.seller_id = seller.seller_id INNER JOIN land ON agreement.land_id = land.land_id").fetchall()
        return agreement

    def post(self):
        """Api to add agreement in the database"""

        agreement = request.get_json(force=True)
        agreement_code = agreement['agreement_code']
        seller_id = agreement['seller_id']
        land_id = agreement['land_id']
        buy_code = agreement['buy_code']
        number = agreement['number']
        conn.execute('''INSERT INTO agreement(agreement_code, seller_id, land_id, buy_code, number) VALUES(?,?,?,?,?)''', (agreement_code, seller_id, land_id, buy_code, number))
        conn.commit()
        return agreement

class Agreement(Resource):
    """This contain all api doing activity with single agreement"""

    def get(self,agreement_code):
        """retrive a singe agreement details by its seller_id"""

        agreements = conn.execute("SELECT * FROM agreement WHERE agreement_code=?",(agreement_code,)).fetchall()
        return agreement


    def delete(self,agreement_code):
        """Delete the agreement by its seller_id"""

        conn.execute("DELETE FROM agreement WHERE agreement_code=?",(agreement_code,))
        conn.commit()
        return {'msg': 'sucessfully deleted'}

    def put(self,agreement_code):
        """Update the agreements details by the seller_id"""

        agreement = request.get_json(force=True)
        agreement_code = agreement['agreement_code']
        seller_id = agreement['seller_id']
        land_id = agreement['land_id']
        buy_code = agreement['buy_code']
        agreement = agreement['agreement']
        conn.execute("UPDATE agreement SET agreement_code=?,seller_id=?,land_id=?,buy_code=?,number=?, WHERE agreement_code=?", (number, buy_code, land_id,  seller_id, agreement_code))
        conn.commit()
        return agreement