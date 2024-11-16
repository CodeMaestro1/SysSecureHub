
if(document.location.hash){
	let uname = document.location.hash.split("#")[1];
	// console.log("Extracted username:", uname);
	if(uname.includes("%")) uname = decodeURI(uname); // We fetch this from the URL, so it *might* contain encoded characters; decode it
	document.write(`<h2>Welcome ${uname}!</h2>`); // Greet the user!
}