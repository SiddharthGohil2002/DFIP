from app.main import app
def test_routes_exist():
    paths={r.path for r in app.routes}
    assert '/health' in paths and '/api/auth/login' in paths and '/api/evidence/upload' in paths
    assert '/api/auth/register' in paths
