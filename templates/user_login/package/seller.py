from flask_restful import Resource, Api, request
from package.model import conn
class Sellers(Resource):
    """This contain apis to carry out activity with all sellers"""

    def get(self):
        """Retrive list of all the seller"""

        sellers = conn.execute("SELECT * FROM seller ORDER BY seller_date DESC").fetchall()
        return sellers



    def post(self):
        """Add the new seller"""

        sellerInput = request.get_json(force=True)
        seller_first_name=sellerInput['seller_first_name']
        seller_last_name = sellerInput['seller_last_name']
        seller_ph_no = sellerInput['seller_ph_no']
        seller_address = sellerInput['seller_address']
        sellerInput['seller_id']=conn.execute('''INSERT INTO seller(seller_first_name,seller_last_name,seller_ph_no,seller_address)
            VALUES(?,?,?,?)''', (seller_first_name, seller_last_name,seller_ph_no,seller_address)).lastrowid
        conn.commit()
        return sellerInput

class Seller(Resource):
    """It include all the apis carrying out the activity with the single seller"""


    def get(self,id):
        """get the details of the seller by the seller id"""

        seller = conn.execute("SELECT * FROM seller WHERE seller_id=?",(id,)).fetchall()
        return seller

    def delete(self, id):
        """Delete the seller by its id"""

        conn.execute("DELETE FROM seller WHERE seller_id=?", (id,))
        conn.commit()
        return {'msg': 'sucessfully deleted'}

    def put(self,id):
        """Update the seller by its id"""

        sellerInput = request.get_json(force=True)
        seller_first_name=sellerInput['seller_first_name']
        seller_last_name = sellerInput['seller_last_name']
        seller_ph_no = sellerInput['seller_ph_no']
        seller_address = sellerInput['seller_address']
        conn.execute(
            "UPDATE seller SET seller_first_name=?,seller_last_name=?,seller_ph_no=?,seller_address=? WHERE seller_id=?",
            (seller_first_name, seller_last_name, seller_ph_no, seller_address, id))
        conn.commit()
        return sellerInput