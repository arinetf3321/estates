

from flask_restful import Resource, Api, request
from package.model import conn



class Locations(Resource):
    """This contain apis to carry out activity with all locations"""

    def get(self):
        """Retrive all the location and return in form of json"""

        location = conn.execute("SELECT * from location").fetchall()
        return location

    def post(self):
        """Api to add location in the database"""

        location = request.get_json(force=True)
        plot_id = location['plot_id']
        name = location['name']
        lc_id = location['lc_id']
        size = location['size']
        conn.execute('''INSERT INTO location(plot_id, name, lc_id, size) VALUES(?,?,?,?)''', (plot_id, name, lc_id, size))
        conn.commit()
        return location



class Location(Resource):
    """This contain all api doing activity with single location"""

    def get(self,plot_id):
        """retrive a singe caveat details by its code"""

        location = conn.execute("SELECT * FROM location WHERE plot_id=?",(plot_id,)).fetchall()
        return location


    def delete(self,plot_id):
        """Delete teh location by its location"""

        conn.execute("DELETE FROM location WHERE plot_id=?",(plot_id,))
        conn.commit()
        return {'msg': 'sucessfully deleted'}

    def put(self,plot_id):
        """Update the location details by the plot_id"""

        location = request.get_json(force=True)
        name = location['name']
        lc_id = location['lc_id']
        size = location['size']
        conn.execute("UPDATE location SET name=?,lc_id=?,size=? WHERE plot_id=?", (name, lc_id, size, plot_id))
        conn.commit()
        return location