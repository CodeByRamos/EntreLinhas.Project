web: (python -m flask db upgrade || echo "db upgrade pulado/falhou — create_all/ensure cuidam do schema") ; gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 60
