class PKCEAuth {
  constructor(aConfig, aCustomRestore, aCustomSetter) {
    let _currentState = "unknown";
    let _config = aConfig;
    let _customRestoreFunc, _postAuthFunc, 
      _customSetterFunc, verifier, code_challenge, code_verifier;

      if (aCustomRestore !== undefined) {
        this.setCustomRestoreFunc(aCustomRestore);
      }
      if (aCustomSetter !== undefined) {
        this.setCustomSetterFunc(aCustomSetter);
      }

    // Generate a secure random string using the browser crypto functions
    const generateRandomString = () => {
      const array = new Uint32Array(28);
      window.crypto.getRandomValues(array);
      return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('');
    }

    // Calculate the SHA256 hash of the input text.
    // Returns a promise that resolves to an ArrayBuffer
    const sha256 = (plain) => {
      const encoder = new TextEncoder();
      const data = encoder.encode(plain);
      return window.crypto.subtle.digest('SHA-256', data);
    }

    // Base64-urlencodes the input string
    const base64urlencode = (str) => {
      // Convert the ArrayBuffer to string using Uint8 array to conver to what btoa accepts.
      // btoa accepts chars only within ascii 0-255 and base64 encodes them.
      // Then convert the base64 encoded to base64url encoded
      // (replace + with -, replace / with _, trim trailing =)
      return btoa(String.fromCharCode.apply(null, new Uint8Array(str))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    // Return the base64-urlencoded sha256 hash for the PKCE challenge
    const pkceChallengeFromVerifier = async (v) => {
      const hashed = await sha256(v);
      return base64urlencode(hashed);
    }


    const getPKCEChallengePair = async () => {
      // Create and store a random "state" value
      verifier = generateRandomString();
       
      // Create and store a new PKCE code_verifier (the plaintext random secret)
      code_verifier = generateRandomString();
       
      
      // Hash and base64-urlencode the secret to use as the challenge
      code_challenge = await pkceChallengeFromVerifier(code_verifier);

      return { verifier, code_challenge };
    }

    this.toString = () => {
      return `${
        JSON.stringify(_config)
      } ${
        _customSetterFunc ? "custom setter function configured" : "No custom setter"
      } ${
        _customRestoreFunc ? "custom restore function configured" : "No custom restore"
      }`
    }
    this.setCustomRestoreFunc = (func) => {
      if (func.constructor.name === "AsyncFunction") {
        _customRestoreFunc = func;
      } else {
        throw new Error("Customer Restore Function must be async ")
      }
    }

    this.setCustomSetterFunc = (func) => {
      if (func.constructor.name === "AsyncFunction") {
        _customSetterFunc = func;
      } else {
        throw new Error("Custom Setter Function must be async ")
      }
    }

    this.setPostAuthorizeFunc = (func) =>{
      if (func.constructor.name === "AsyncFunction") {
        _postAuthFunc = func;
      } else {
        throw new Error("Post Authorize Function must be async ")
      }
    }

    this.setConfig = (aConfig) => {
      _config = aConfig;
    }

    this.getAuthoriseUrl = (challengePair) => {
      const sUrl = `${_config.authorizeEndpoint}?state=${encodeURIComponent(challengePair.verifier)}&scope=${encodeURIComponent(_config.scope)}&response_type=code&client_id=${encodeURIComponent(_config.clientId)}&code_challenge=${encodeURIComponent(challengePair.code_challenge)}&code_challenge_method=S256&redirect_uri=${encodeURIComponent(_config.redirectUri)}`;
 
        return sUrl
    }

    this.authorize = async () =>{
      // TODO restore stuff here from storage 
      const cv = window.sessionStorage.getItem("pkce_code_verifier");
     
      // TODO change this based on storage and is valid 
      if (!cv) {
        // first thing initialize
        const pairs = await getPKCEChallengePair();

        const url = this.getAuthoriseUrl(pairs);
        console.log("authorizing .....");
        window.sessionStorage.setItem("pkce_code_verifier", code_verifier);

        
        window.location.href = url;
        // use these to auth 
        // call postAuthFunc if set 

      } else {
        //console.log('cccccvvvvvv', cv, window.location.search );
        const code = new URLSearchParams(location.search).get("code");

        // get access tokens here 
        const params = {
          "grant_type": "authorization_code",
          "client_id": _config.clientId,
          "code_verifier": cv,
          "code": code,
          "redirect_uri": _config.redirectUri
        };

        const r = await fetch(_config.tokenEndpoint, {
          method: "POST",
          headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
          body: Object.keys(params).map((key) => {
            return encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
          }).join('&')
        });

        if (r.status === 200 ) {
          const auth_keys = await r.json();
          console.log('auth keys are ', auth_keys);
          // refreshTokens(auth_keys.refresh_token);
          // TODO remove this 
          const logout = this.logout;
          setTimeout(()=>{
            console.log('i should be logging out ')
            logout();
          }, 10000);
          _currentState = "authorized";
        }
        
      }

    }

    this.logout = () =>{
   
      const url = `${_config.logoutEndpoint}?redirect_uri=${encodeURIComponent(_config.redirectUri)}`;
      window.localStorage.clear();
      window.sessionStorage.clear();
      window.location.href = url;
    }

    this.isAuthorized = () => {
      return _currentState === "authorized";
    }

    this.getAccessToken = () => {
      //TODO return here check stuff 

    }

    const refreshTokens = async (refresh_token) =>{
      var myHeaders = new Headers();
      myHeaders.append("Content-Type", "application/x-www-form-urlencoded");
      
      var urlencoded = new URLSearchParams();
      urlencoded.append("grant_type", "refresh_token");
      urlencoded.append("refresh_token", refresh_token);
      urlencoded.append("client_id", _config.clientId);
      
      var requestOptions = {
        method: 'POST',
        headers: myHeaders,
        body: urlencoded
      };


          const rObject = await fetch(`${_config.tokenEndpoint}`, requestOptions);
          const refreshedData = await rObject.json();
  
          console.log('refresh access token returned: ', refreshedData);
          // TODO ...save it here
          return refreshedData;

    }

  }

}

module.exports = PKCEAuth;
