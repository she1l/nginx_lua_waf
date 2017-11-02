function pass()
    local list = {}
    local path = "/application/nginx/conf/waf/whitelist"
    local file = io.open(path, "r")

    for line in file:lines() do
        table.insert(list, line)
    end
    file:close()

    if next(list) ~= nil then
        for _, ip in ipairs(list) do
            if ngx.var.remote_addr == ip then
                return true
            end
        end
    end
    return false
end


function block()
    local list = {}
    local path = "/application/nginx/conf/waf/blacklist"
    local file = io.open(path, "r")

    for line in file:lines() do
        table.insert(list, line)
    end
    file:close()

    if next(list) ~= nil then
        for _, ip in ipairs(list) do
            if ngx.var.remote_addr == ip then
                ngx.exit(403)
                return true
            end
        end
    end
    return false
end


function deny()
    local count = 10
    local seconds = 60

    local urilist = {
        "/api/OfflineMemberApi/PostSMSCode",
        "/api/OfflineMemberApi",
    }

    local rexuri = string.match(ngx.var.request_uri, "^[/a-zA-Z]*")
    local path = "/application/nginx/conf/waf/blacklist"

    if next(urilist) ~= nil then
        for _, uri in ipairs(urilist) do
            if string.lower(uri) == string.lower(rexuri) then
                local token = ngx.var.remote_addr..uri
                local limit = ngx.shared.limit
                local req, _ = limit:get(token)
                if req then
                    if req > count then
                        ngx.header.content_type = "text/html"
                        local file = io.open(path, "ab")

                        file:write(ngx.var.remote_addr.."\n")
                        file:flush()
                        file:close()
                        ngx.exit(403)
                    else
                        limit:incr(token,1)
                    end
                else
                    limit:set(token, 1, seconds)
                end
            end
        end
    end
end
