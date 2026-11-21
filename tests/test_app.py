import pytest
from app.main import safe_rel, validate_url

def test_path_preserves_hierarchy():
    assert safe_rel('https://example.com/products/widget',True) == 'products/widget/index.html'
    assert safe_rel('https://example.com/a.css',False) == 'a.css'

def test_different_query_paths():
    assert safe_rel('https://example.com/a?x=1',True) != safe_rel('https://example.com/a?x=2',True)

@pytest.mark.parametrize('url', [
    'file:///etc/passwd','http://localhost/private','http://127.0.0.1/',
    'https://example.com:8080/admin','http://user:password@example.com',
])
def test_private_or_invalid_urls(url):
    with pytest.raises(ValueError):
        validate_url(url)

def test_health_endpoint():
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as client:
        assert client.get('/health').json() == {'status':'ok'}
        assert client.get('/').status_code == 200

def test_archive_path_contains_no_parent_traversal():
    for url in ('https://example.com/a/%2e%2e/x', 'https://example.com/a/..%2F..%2Fsecret'):
        rel=safe_rel(url,True)
        assert not rel.startswith('/')
        assert '..' not in rel.split('/')
