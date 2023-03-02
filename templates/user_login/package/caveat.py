

from flask_restful import Resource, Api, request
from package.model import conn



class Caveats(Resource):
    """This contain apis to carry out activity with all caveats"""

    def get(self):
        """Retrive all the caveat and return in form of json"""

        caveat = conn.execute("SELECT * from caveat").fetchall()
        return caveat

    def post(self):
        """Api to add caveat in the database2"""

        caveat = request.get_json(force=True)
        code = caveat['code']
        name = caveat['name']
        brand = caveat['brand']
        description = caveat['description']
        conn.execute('''INSERT INTO caveat(code, name, brand, description) VALUES(?,?,?,?)''', (code, name, brand, description))
        conn.commit()
        return caveat



class Caveat(Resource):
    """This contain all api doing activity with single caveat"""

    def get(self,code):
        """retrive a singe caveat details by its code"""

        caveat = conn.execute("SELECT * FROM caveat WHERE code=?",(code,)).fetchall()
        return caveat


    def delete(self,code):
        """Delete teh caveat by its caveat"""

        conn.execute("DELETE FROM caveat WHERE code=?",(code,))
        conn.commit()
        return {'msg': 'sucessfully deleted'}

    def put(self,code):
        """Update the caveat details by the code"""

        caveat = request.get_json(force=True)
        name = caveat['name']
        brand = caveat['brand']
        description = caveat['description']
        conn.execute("UPDATE caveat SET name=?,brand=?,description=? WHERE code=?", (name, brand, description, code))
        conn.commit()
        return caveat