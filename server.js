const fs = require("fs"),
	https = require("https"),
	crypto = require("crypto"),
	readline = require("readline");
const store = "store.json";
const allowManyRequests = true;
const options = {
	key: fs.readFileSync("key.pem"),
	cert: fs.readFileSync("cert.pem")
};
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
rl.question("Encryption passphrase: ", (r) => {
	const ehash = crypto.createHash("sha256");
	ehash.update(Buffer.from(r));
	const enc = ehash.digest();
	if (!enc) return;
	const server = https.createServer(options, (req, res) => {
		if (req.method == "POST") {
			const h = req.headers;
			console.log("---\nIncoming: ", req.url, "\n", h);
			const socket = req.socket; //socket.remoteAddress: IP
			let data, st = {}; //data: buffer
			if (fs.existsSync(store)) {
				const f = fs.readFileSync("store.json");
				st = JSON.parse(f);
				if (!st) res.end(500);
			} else {
				console.log("Creating store.json.");
				fs.writeFileSync("store.json", JSON.stringify({}));
			}
			const ip = socket.remoteAddress;
			let Status = 400, Headers = {}, Body = ""; //return data
			if (!st.iplog) {
				st.iplog = {};
				st.iplog[ip] = Date.now();
				fs.writeFileSync(store, JSON.stringify(st));
			}
			const tl = Date.now() - st.iplog[ip]; //time since last request
			if (tl < 15000 && allowManyRequests == false) {
				Status = 429; //Too Many Requests
			} else {
				st.iplog[ip] = Date.now();
				fs.writeFileSync(store, JSON.stringify(st));
			}
			req.on("data", (chunk) => {
				data = Buffer.from(chunk);
			});
			req.on("end", () => {
				if (!data) Status = 406;
				else {
					console.log("buf[" + data.length + "] " + data.toString("hex"));
				}
				if (Status == 429) { //prevent DDoS
					console.log("delaying request from", ip);
				} else {
					if (req.url == "/key") {
						if (data.length != 32) { //AES key length
							Status = 406; //Not Acceptable
						} else {
							const hash = crypto.createHash("sha512");
							hash.update(data);
							const id = hash.digest();
							const aes = crypto.createCipheriv("aes256", enc, Buffer.alloc(16));
							const key1 = aes.update(data);
							const key2 = aes.final();
							const key = Buffer.concat([key1, key2]);
							const obj = {
								"id": id.toString("hex"),
								"key": key.toString("hex"),
								"unlocked": false,
								"ip": ip
							};
							if (!st[id]) {
								console.log("-> Storing:\n", obj);
								st[id] = obj;
								fs.writeFileSync(store, JSON.stringify(st));
							}
							Status = 201; //Created
							Headers["Content-Type"] = "application/octet-stream";
							Body = id; //give id
						}
					} else if (req.url == "/id") {
						if (data.length != 512 / 8) { //SHA512 hash length
							Status = 406;
						} else {
							const id = data;
							if (st[id]) {
								let key = Buffer.from(st[id]["key"], "hex"); //build buffer from hex string
								//check if hash(dec(key))=id
								const aes = crypto.createDecipheriv("aes256", enc, Buffer.alloc(16));
								const key1 = aes.update(key);
								const key2 = aes.final();
								key = Buffer.concat([key1, key2]);
								const hash = crypto.createHash("sha512");
								hash.update(key);
								const rev = hash.digest();
								console.log(id, rev, Buffer.compare(id, rev));
								if (Buffer.compare(id, rev) != 0) {
									Status = 401; //Unauthorized
									console.log("key hash =/= given id");
								} else {
									console.log("-> unlocked: ", st[id]["unlocked"]);
									if (st[id]["unlocked"] == true) {
										Status = 200;
										Headers["Content-Type"] = "application/octet-stream";
										Body = key;
									} else {
										Status = 402; //Payment Required
									}
								}
							} else {
								Status = 404; //Not Found
							}
						}
					}
				}
				res.writeHead(Status, Headers);
				res.end(Body);
				console.log("Outgoing: ", Status, "\n", Body, "\n---\n");
			});
		} else {
			res.writeHead(405, "Method not allowed");
			res.end();
		}

	}).listen(5500);
}); //end of rl.question