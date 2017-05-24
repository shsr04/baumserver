NODE=../nodejs-v6/bin/node

server: server.js
	$(NODE) server.js 2>server_err.log

client: client.js
	$(NODE) client.js

clean: store.json
	echo '{}' > store.json