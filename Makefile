test:
	curl -X POST -H 'content-type: application/json' --data '{"id": "2"}' http://localhost:8080/users > token.json
refresh:
	curl -X POST -H 'content-type: application/json' -d "@token.json" http://localhost:8080/refresh