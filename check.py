from app import app, get_db
with app.app_context():
    c = get_db()
    scan = c.execute('SELECT * FROM scans WHERE id=1').fetchone()
    print(dict(scan))
