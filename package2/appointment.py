from flask_restful import Resource, Api, request
from package.model import conn



class Appointments(Resource):
    """This contain apis to carry out activity with all appiontments"""

    def get(self):
        """Retrive all the appointment and return in form of json"""

        appointment = conn.execute("SELECT l.*,s.*,a.* from appointment a LEFT JOIN land l ON a.land_id = l.land_id LEFT JOIN seller s ON a.seller_id = s.seller_id ORDER BY appointment_date DESC").fetchall()
        return appointment

    def post(self):
        """Create the appoitment by assiciating patient and docter with appointment date"""

        appointment = request.get_json(force=True)
        land_id = appointment['land_id']
        seller_id = appointment['seller_id']
        appointment_date = appointment['appointment_date']
        appointment['app_id'] = conn.execute('''INSERT INTO appointment(land_id,seller_id,appointment_date)
            VALUES(?,?,?)''', (land_id, seller_id,appointment_date)).lastrowid
        conn.commit()
        return appointment



class Appointment(Resource):
    """This contain all api doing activity with single appointment"""

    def get(self,app_id):
        """retrive a singe appointment details by its id"""

        appointment = conn.execute("SELECT * FROM appointment WHERE app_id=?",(app_id,)).fetchall()
        return appointment


    def delete(self,app_id):
        """Delete teh appointment by its id"""

        conn.execute("DELETE FROM appointment WHERE app_id=?",(app_id,))
        conn.commit()
        return {'msg': 'sucessfully deleted'}

    def put(self,app_id):
        """Update the appointment details by the appointment id"""

        appointment = request.get_json(force=True)
        land_id = appointment['land_id']
        seller_id = appointment['seller_id']
        conn.execute("UPDATE appointment SET land_id=?,seller_id=? WHERE app_id=?",
                     (land_id, seller_id, app_id))
        conn.commit()
        return appointment