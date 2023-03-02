from flask_restful import Resource, Api, request
from package.model import conn



class Buy_sell_transactions(Resource):
    """This contain apis to carry out activity with all buy_sell_transaction"""

    def get(self):
        """Retrieve all the buy_sell_transaction and return in form of json"""

        buy_sell_transaction = conn.execute("SELECT * from buy_sell_transaction").fetchall()
        #buy_sell_transaction = conn.execute("SELECT buy_sell_transaction.seller_id, seller.seller_first_name, seller.seller_last_name, buy_sell_transaction.land_id, land.landowner_first_name, land.landowner_last_name, buy_sell_transaction.buy_code, buy_sell_transaction.buy_date, buy_sell_transaction.buyer_id, buyer.buyer_first_name, buyer.buyer_last_name, buy_sell_transaction.land_title_no FROM buy_sell_transaction INNER JOIN seller ON buy_sell_transaction.seller_id = seller.seller_id INNER JOIN land ON buy_sell_transaction.land_id = land.land_id INNER JOIN buyer ON buy_sell_transaction.buyer_id = buyer.buyer_id").fetchall()
        return buy_sell_transaction

    def post(self):
        """Api to add buy_sell_transaction in the database2"""

        buy_sell_transaction = request.get_json(force=True)
        land_id = buy_sell_transaction['land_id']
        buy_code = buy_sell_transaction['buy_code']
        buy_date = buy_sell_transaction['buy_date']
        seller_id = buy_sell_transaction['seller_id']
        buyer_id = buy_sell_transaction['buyer_id']
        land_title_no = buy_sell_transaction['land_title_no']
        conn.execute('''INSERT INTO buy_sell_transaction(land_id, buy_code, buy_date, seller_id, buyer_id, land_title_no) VALUES(?,?,?,?,?,?)''', (land_id, buy_code, buy_date, seller_id, buyer_id, land_title_no))
        conn.commit()
        return buy_sell_transaction



class Buy_sell_transaction(Resource):
    """This contain all api doing activity with single buy_sell_transaction"""

    def get(self,land_id):
        """retrive a single buy_sell_transaction details by its land_id"""

        buy_sell_transaction = conn.execute("SELECT * FROM buy_sell_transaction WHERE land_id=?",(land_id,)).fetchall()
        return buy_sell_transaction


    def delete(self,land_id):
        """Delete the buy_sell_transaction by its seller_id"""

        conn.execute("DELETE FROM buy_sell_transaction WHERE land_id=?",(land_id,))
        conn.commit()
        return {'msg': 'sucessfully deleted'}

    def put(self,land_id):
        """Update the buy_sell_transaction details by the seller_id"""

        buy_sell_transaction = request.get_json(force=True)
        land_id = buy_sell_transaction['land_id']
        buy_code = buy_sell_transaction['buy_code']
        buy_date = buy_sell_transaction['buy_date']
        seller_id = buy_sell_transaction['seller_id']
        buyer_id = buy_sell_transaction['buyer_id']
        land_title_no = buy_sell_transaction['land_title_no']
        conn.execute("UPDATE buy_sell_transaction SET land_id=?,buy_code=?,buy_date=?,seller_id=?,buyer_id=?,land_title_no=?, WHERE land_id=?", (land_id, buy_code, buy_date, seller_id, buyer_id, land_title_no))
        conn.commit()
        return buy_sell_transaction           