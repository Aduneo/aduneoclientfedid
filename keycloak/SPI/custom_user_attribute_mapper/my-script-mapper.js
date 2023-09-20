

/**
 * Change value to "true" in order to enable debugging
 * output to /var/log/keycloak/keycloak.log.
 */
var debug = false
var ArrayList = Java.type("java.util.ArrayList");
//var bindings = javax.script.Bindings;
var myList = new ArrayList();
myList.add(user.username);
myList.add(user.realm);


// The 'user' and 'token' objects are bound to the script context automatically
var userAttribute = user.getAttribute("id");
if (userAttribute !== null && userAttribute.size() > 0) {
    token.setOtherClaims("newClaim", userAttribute.get(0));
}


/**
 * The actual debug output function
 */
function debugOutput(msg) {
    if (debug) print("Debug script mapper: " + msg);
}



debugOutput('final array ' + myList);
exports = myList;
