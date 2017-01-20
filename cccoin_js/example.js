var Offchain = require('./offchain'),
    
    // Create a new instance, with optional API key and secret
    xoc = new offchain(
	// 'API_KEY',
	// 'API_SECRET'
    );


// Optionally turn off SSL certificate checking
// Offchain.STRICT_SSL = false; 


// Public call
xoc.getTicker(function(err, data){
    if (err){
        console.log('ERROR', err);
        return;
    }
    console.log(data);
});
