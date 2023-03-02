

from flask_restful import Resource, Api, request
from package.model import conn



class Procedures(Resource):
    """This contain apis to carry out activity with all procedures"""

    def get(self):
        """Retrive all the procedure and return in form of json"""

        procedure = conn.execute("SELECT * from procedure").fetchall()
        return procedure

    def post(self):
        """Api to add procedure in the database"""

        procedure = request.get_json(force=True)
        buy_code = procedure['buy_code']
        name = procedure['name']
        cost = procedure['cost']
        description = procedure['description']
        conn.execute('''INSERT INTO procedure(buy_code, name, cost, description) VALUES(?,?,?,?)''', (buy_code, name, cost, description))
        conn.commit()
        return procedure



class Procedure(Resource):
    """This contain all api doing activity with single procedure"""

    def get(self,buy_code):
        """retrive a singe procedure details by its buy_code"""

        procedure = conn.execute("SELECT * FROM procedure WHERE buy_code=?",(buy_code,)).fetchall()
        return procedure


    def delete(self,buy_code):
        """Delete teh procedure by its caveat"""

        conn.execute("DELETE FROM procedure WHERE buy_code=?",(buy_code,))
        conn.commit()
        return {'msg': 'sucessfully deleted'}

    def put(self,buy_code):
        """Update the procedure details by the buy_code"""

        procedure = request.get_json(force=True)
        name = procedure['name']
        cost = procedure['cost']
        description = procedure['description']
        conn.execute("UPDATE procedure SET name=?,cost=?,description=? WHERE buy_code=?", (name, cost, description, buy_code))
        conn.commit()
        return procedure