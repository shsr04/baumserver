var https = require('https'),
	crypto = require('crypto'),
	fs = require('fs');
var ip = '10.195.0.39';
ip = 'localhost'; //enable if needed
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
var hash;
if (fs.existsSync('store.json')) fs.unlinkSync('store.json');
function send(pPath, pPayload, pOnData) {
	https.request({
		protocol: 'https:',
		host: ip,
		port: 5500,
		path: pPath,
		method: 'POST',
		headers: {
			'Content-Type': 'application/octet-stream'
		},
		agent: false
	}, pOnData).end(pPayload);
}
send('/key', 'BINARY_KEY_DATA_32_BYTES_LENGTH_', (res) => {
	res.on('data', (chunk) => {
		hash = Buffer.from(chunk); //MUST be converted to buffer
		console.log(hash);
		send('/id', hash);
	});
});