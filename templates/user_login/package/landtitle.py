

from flask_restful import Resource, Api, request
from package.model import conn



class Landtitles(Resource):
    """This contain apis to carry out activity with all caveats"""

    def get(self):
        """Retrive all the caveat and return in form of json"""

        landtitle = conn.execute("SELECT * from landtitle").fetchall()
        return landtitle

    def post(self):
        """Api to add landtitle in the database2"""

        landtitle = request.get_json(force=True)
        land_title_no = landtitle['land_title_no']
        name = landtitle['name']
        available = landtitle['available']
        description = landtitle['description']
        conn.execute('''INSERT INTO landtitle(land_title_no, name, available, description) VALUES(?,?,?,?)''', (land_title_no, name, available, description))
        conn.commit()
        return landtitle



class Landtitle(Resource):
    """This contain all api doing activity with single landtitle"""

    def get(self,land_title_no):
        """retrive a singe landtitle details by its code"""

        landtitle = conn.execute("SELECT * FROM landtitle WHERE land_title_no=?",(land_title_no,)).fetchall()
        return landtitle


    def delete(self,land_title_no):
        """Delete teh landtitle by its caveat"""

        conn.execute("DELETE FROM landtitle WHERE land_title_no=?",(land_title_no,))
        conn.commit()
        return {'msg': 'sucessfully deleted'}

    def put(self,land_title_no):
        """Update the caveat details by the code"""

        landtitle = request.get_json(force=True)
        name = landtitle['name']
        available = landtitle['available']
        description = landtitle['description']
        conn.execute("UPDATE landtitle SET name=?,available=?,description=? WHERE land_title_no=?", (name, available, description, land_title_no))
        conn.commit()
        return landtitle