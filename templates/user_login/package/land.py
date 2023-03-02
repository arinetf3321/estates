from flask_restful import Resource, Api, request
from package.model import conn

class Lands(Resource):
    """It contain all the api carryign the activity with and specific land"""

    def get(self):
        """Api to retive all the land from the database"""

        lands = conn.execute("SELECT * FROM land ORDER BY landowneracq_date DESC").fetchall()
        return lands



    def post(self):
        """api to add the land in the database"""

        landInput = request.get_json(force=True)
        landowner_first_name=landInput['landowner_first_name']
        landowner_last_name = landInput['landowner_last_name']
        landowner_insurance_no = landInput['landowner_insurance_no']
        landowner_ph_no = landInput['landowner_ph_no']
        landowner_address = landInput['landowner_address']
        landInput['land_id']=conn.execute('''INSERT INTO land(landowner_first_name,landowner_last_name,landowner_insurance_no,landowner_ph_no,landowner_address)
            VALUES(?,?,?,?,?)''', (landowner_first_name, landowner_last_name, landowner_insurance_no,landowner_ph_no,landowner_address)).lastrowid
        conn.commit()
        return landInput

class Land(Resource):
    """It contains all apis doing activity with the single land entity"""

    def get(self,id):
        """api to retrive details of the land by its id"""

        land = conn.execute("SELECT * FROM land WHERE land_id=?",(id,)).fetchall()
        return land

    def delete(self,id):
        """api to delete the land by its id"""

        conn.execute("DELETE FROM land WHERE land_id=?",(id,))
        conn.commit()
        return {'msg': 'sucessfully deleted'}

    def put(self,id):
        """api to update the land by it id"""

        landInput = request.get_json(force=True)
        landowner_first_name = landInput['landowner_first_name']
        landowner_last_name = landInput['landowner_last_name']
        landowner_insurance_no = landInput['landowner_insurance_no']
        landowner_ph_no = landInput['landowner_ph_no']
        landowner_address = landInput['landowner_address']
        conn.execute("UPDATE land SET landowner_first_name=?,landowner_last_name=?,landowner_insurance_no=?,landowner_ph_no=?,landowner_address=? WHERE land_id=?",
                     (landowner_first_name, landowner_last_name, landowner_insurance_no,landowner_ph_no,landowner_address,id))
        conn.commit()
        return landInput