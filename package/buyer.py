from flask_restful import Resource, Api, request
from package.model import conn
class Buyers(Resource):
    """This contain apis to carry out activity with all buyers"""

    def get(self):
        """Retrive list of all the buyer"""

        buyers = conn.execute("SELECT * FROM buyer ORDER BY buy_date DESC").fetchall()
        return buyers



    def post(self):
        """Add the new buyer"""

        buyerInput = request.get_json(force=True)
        buyer_first_name=buyerInput['buyer_first_name']
        buyer_last_name = buyerInput['buyer_last_name']
        buyer_ph_no = buyerInput['buyer_ph_no']
        buyer_address = buyerInput['buyer_address']
        buyerInput['buyer_id']=conn.execute('''INSERT INTO buyer(buyer_first_name,buyer_last_name,buyer_ph_no,buyer_address)
            VALUES(?,?,?,?)''', (buyer_first_name, buyer_last_name,buyer_ph_no,buyer_address)).lastrowid
        conn.commit()
        return buyerInput

class Buyer(Resource):
    """It include all the apis carrying out the activity with the single buyer"""


    def get(self,id):
        """get the details of the buyer by the buyer id"""

        buyer = conn.execute("SELECT * FROM buyer WHERE buyer_id=?",(id,)).fetchall()
        return buyer

    def delete(self, id):
        """Delete the buyer by its id"""

        conn.execute("DELETE FROM buyer WHERE buyer_id=?", (id,))
        conn.commit()
        return {'msg': 'sucessfully deleted'}

    def put(self,id):
        """Update the buyer by its id"""

        buyerInput = request.get_json(force=True)
        buyer_first_name=buyerInput['buyer_first_name']
        buyer_last_name = buyerInput['buyer_last_name']
        buyer_ph_no = buyerInput['buyer_ph_no']
        buyer_address = buyerInput['buyer_address']
        conn.execute(
            "UPDATE buyer SET buyer_first_name=?,buyer_last_name=?,buyer_ph_no=?,buyer_address=? WHERE buyer_id=?",
            (buyer_first_name, buyer_last_name, buyer_ph_no, buyer_address, id))
        conn.commit()
        return buyerInput