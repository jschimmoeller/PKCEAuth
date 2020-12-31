```javascript 
/*react code */
  useEffect(()=>{

      const X  = new auth({
        clientId: 'UYlQ9eg7x7mMDSJszvHx',
        authorizeEndpoint: 'https://auth-appdev.star2starglobal.net/oauth/authorize',
        scope: 'openid',
        redirectUri: 'http://localhost:3001',
        tokenEndpoint: 'https://auth-appdev.star2starglobal.net/oauth/token',
        logoutEndpoint: 'https://auth-appdev.star2starglobal.net/sso/logout'
      })
      
   
      X.authorize();


  },[])
  ```