## Project Structure

```bash
/src
   /analysis.js     
   /license.js      
   /cli.js          
/package.json
/.env
```

## Preparation

Run `npm install`
Run `repomix` to pack the repository
Configure API keys in `.env`

## Local Development
Run `node server.js` to start the server

Test login at http://localhost:3000/auth/github
(Make sure the Authorization callback URL is set to the url - configure it at github.com/settings/applications/id )

Upon successful authorization, you should be redirected to:
http://localhost:3000/dashboard

Open developer tool (F12) > Application > Cookies > connect.sid (copy value)

Test `/summarize` endpoint by sending a POST request with the cookie (Postman > Headers > Key/Value. Key: Cookie, Value: connect.sid=...)
Make sure to include a repoUrl in the Body (Raw JSON):
```
{
  "repoUrl": "https://github.com/facebook/react"
}
```

Note we can run Repomix on the local directory with custom settings (e.g. NO_COLOUR)


## Debugging

`/summarize`:

 - Error code 401: Check OpenAI API


