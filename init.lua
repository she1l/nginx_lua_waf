-- 加载白名单
whiteList = {}
whiteListFile = io.open("/application/nginx/conf/waf/whitelist", "r")
for line in whiteListFile:lines() do
    table.insert(whiteList, line)
end
whiteListFile.close()


-- 加载黑名单
blackList = {}
blackListFile = io.open("/application/nginx/conf/waf/blacklist", "r")
for line in blackListFile:lines() do
    table.insert(blackList, line)
end
blackListFile.close()


-- 白名单 pass 方法
function pass()
    if next(whiteList) ~= nil then
        for _, ip in ipairs(whiteList) do
            if ngx.var.remote_addr == ip then
                return true
            end
        end
    end
    return false
end


-- 黑名单 block 方法
function block()
    if next(blackList) ~= nil then
        for _, ip in ipairs(blackList) do
            if ngx.var.remote_addr == ip then
                ngx.exit(403)
                return true
            end
        end
    end
    return false
end


-- 防 cc 方法
function cc()
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

                        table.insert(blackList, ngx.var.remote_addr)

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


