local cookie = ngx.var.cookie_Auth
local hmac = ""
local timestamp = ""

if cookie ~= nil and cookie:find(":") ~= nil then
    local divider = cookie:find(":")
    hmac = ngx.decode_base64(cookie:sub(divider+1))
    timestamp = cookie:sub(0, divider-1)
    if ngx.hmac_sha1(ngx.var.plex_auth_secret, timestamp) == hmac and tonumber(timestamp) >= ngx.time() then
        if tonumber(timestamp) <= ngx.time() + 1800 then
            local expiration = ngx.time() + ngx.var.plex_auth_expires_after
            local token = expiration .. ":" .. ngx.encode_base64(ngx.hmac_sha1( ngx.var.plex_auth_secret, expiration))
            local cookie = "Auth=" .. token .. "; "
            cookie = cookie .. "Path=/; Domain=" .. ngx.var.server_name .. "; "
            cookie = cookie .. "Expires=" .. ngx.cookie_time(expiration) .. "; "
            cookie = cookie .. "; Max-Age=" .. ngx.var.plex_auth_expires_after .. "; secure; HttpOnly"
            ngx.header["Set-Cookie"] = cookie
        end
        return
    end
else
    if ngx.var.request_method == "POST" then
        local args, err = ngx.req.get_post_args()
        ngx.log(ngx.ERR, "email: ", args["email"])
        ngx.log(ngx.ERR, "password: ", args["password"])
        ngx.log(ngx.ERR, "auth: ", "Authorization", "Basic " .. ngx.encode_base64(args["email"] .. ":" .. args["password"]))
        ngx.req.set_header("Authorization", "Basic " .. ngx.encode_base64(args["email"] .. ":" .. args["password"]))
    end
    local res = ngx.location.capture("/_auth")
    local match = ngx.re.match(res.body, ngx.var.plex_auth_server_ID)
    if match then
        local expiration = ngx.time() + ngx.var.plex_auth_expires_after
        local token = expiration .. ":" .. ngx.encode_base64(ngx.hmac_sha1( ngx.var.plex_auth_secret, expiration))
        local cookie = "Auth=" .. token .. "; "
        cookie = cookie .. "Path=/; Domain=" .. ngx.var.server_name .. "; "
        cookie = cookie .. "Expires=" .. ngx.cookie_time(expiration) .. "; "
        cookie = cookie .. "; Max-Age=" .. ngx.var.plex_auth_expires_after .. "; secure; HttpOnly"
        ngx.header["Set-Cookie"] = cookie
        return
    else
        if ngx.var.http_user_agent == "Android-ownCloud" then
            ngx.header.www_authenticate = [[Basic realm="owncloud login"]]
            ngx.exit(ngx.HTTP_UNAUTHORIZED)
            return
        end
        ngx.header["Content-type"] = "text/html"
        ngx.say([==[
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset="UTF-8"> 
    <title>
        Login
    </title>
</head>
<body>
    <form method="post">
      <h1>Login Page</h1>
      <div class="inset">
      <p>
        <label for="email">ACCOUNT</label>
        <input type="text" required="" name="email" id="email">
      </p>
      <p>
        <label for="password">PASSWORD</label>
        <input type="password" required="" name="password" id="password">
      </p>
      </div>
      <p class="p-container">
        <input type="submit" name="go" id="go" value="Log in" class="button right">
        <input type="reset" name="go" id="go" value="Clear" class="button left">
      </p>
    </form>
</body>
</html>
]==])
        ngx.exit(ngx.HTTP_OK)
        return
    end
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end
