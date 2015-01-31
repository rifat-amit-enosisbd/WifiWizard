/**
 *  WifiConfig constructor. The WifiConfig object is used by WifiWizard
 *  to connect and disconnect networks.
 *
 *  @param  {string}    ssid    The SSID of the network to configure
 *  @param  {WifiAuth}  auth    WifiAuth object to authenticate to the Wifi
 */
function WifiConfig(ssid, auth) {
    var _ssid = null;
    var _auth = null;
    var self = this;

    var WifiAuth = require('WifiAuth');

    this.ssid = function(ssid) {
        if (ssid === undefined) {
            return self._ssid;
        }

        if( ssidIsValid(ssid) ) {
            self._ssid = formatSSID(ssid);
        }
        else {
            throw new Error("SSID Invalid");
        }

        return this;
    };

    this.auth = function(auth) {
        if (auth === undefined) {
            return self._auth; // TODO: Clone object instead of returning reference
        }
        else if (auth instanceof WifiAuth) {
            self._auth = auth;
        }
        else {
            throw new Error("Auth must be object of type WifiAuth");
        }

        return this;
    };

    /**
     *	This method formats a given SSID and ensures that it is appropriate.
     *	If the SSID is not wrapped in double quotes, it wraps it in double quotes.
     * Despite the name, this also needs to be done to WPA PSK.
     *	@param	ssid	the SSID to format
     */
    function formatSSID(ssid) {
        if (ssid === undefined || ssid === null) {
            ssid = "";
        }
        ssid = ssid.trim();

        if (ssid.charAt(0) != '"' ) {
            ssid = '"' + ssid;
        }

        if (ssid.charAt(ssid.length-1) != '"' ) {
            ssid = ssid + '"';
        }

        return ssid;
    }

    function ssidIsValid(ssid) {
        return (typeof ssid === "string" || ssid instanceof String) && ssid.length <= 32;
    }

    // Initialize object
    this.ssid(ssid).auth(auth);
}

module.exports = WifiConfig;