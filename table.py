from main import db

def create_table_if_not_exist():
    try:
        db.create_all()
    except:
        return "Table exist"