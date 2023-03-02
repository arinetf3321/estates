from flask_restful import Resource, Api, request
from package.model import conn



class Projectss(Resource):
    """This contain apis to carry out activity with all projectss"""

    def get(self):
        """Retrive all the projects and return in form of json"""

        # projects = conn.execute("SELECT * from projects").fetchall()
        projects = conn.execute("SELECT projects.project_owner, seller.seller_first_name, seller.seller_last_name, project.project_id, land.landowner_first_name, land.landowner_last_name, projects.project_name, projects.acquired_date, projects.project_location, buyer.buyer_first_name, buyer.buyer_last_name, projects.cost FROM projects INNER JOIN seller ON projects.project_owner = seller.seller_id INNER JOIN land ON projects.project_id = land.land_id INNER JOIN buyer ON projects.project_location = buyer.buyer_id").fetchall()

        return projects

    def post(self):
        """Api to add projects in the database"""

        projects = request.get_json(force=True)
        project_owner = projects['project_owner']
        project_id = projects['project_id']
        project_name = projects['project_name']
        acquired_date = projects['acquired_date']
        app_id = projects['app_id']
        project_location = projects['project_location']
        cost = projects['cost']
        conn.execute('''INSERT INTO projects(project_id, project_name, acquired_date, app_id, project_owner, project_location, cost) VALUES(?,?,?,?,?,?)''', (project_id, project_name, acquired_date, app_id, project_owner, project_location, cost))
        conn.commit()
        return projects



class Projects(Resource):
    """This contain all api doing activity with single projects"""

    def get(self,project_id):
        """retrive a singe projects details by its project_id"""

        projects = conn.execute("SELECT * FROM projects WHERE project_id=?",(project_id,)).fetchall()
        return projects


    def delete(self,project_id):
        """Delete the project by its project_owner"""

        conn.execute("DELETE FROM projects WHERE project_id=?",(project_id,))
        conn.commit()
        return {'msg': 'sucessfully deleted'}

    def put(self,project_id):
        """Update the project details by the project_owner"""

        projects = request.get_json(force=True)
        project_owner = projects['project_owner']
        project_id = projects['project_id']
        project_name = projects['project_name']
        acquired_date = projects['acquired_date']
        app_id = projects['app_id']
        costs = projects['cost']
        conn.execute("UPDATE projects SET project_owner=?,project_id=?,project_name=?,acquired_date=?,app_id=?,cost=?, WHERE project_id=?", (project_owner, project_id, project_name, acquired_date, app_id, cost, project_id))
        conn.commit()
        return projects