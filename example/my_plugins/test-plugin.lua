--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
local core = require("apisix.core")

local tab_insert = table.insert
local tab_concat = table.concat
local re_gmatch = ngx.re.gmatch
local ipairs = ipairs


-- 路由判断
_IDC_NUM_TABLE = { "2", "4", "6", "8", "10", "12" }
_IDC_DESC_TABLE = { "阿里云", "私有云", "澳洲AUS", "欧洲", "新加坡", "美西" }
_IDC_TAG_TABLE = { "mdc-ali", "mdc-private", "mdc-aus", "mdc-eu", "mdc-sgp", "mdc-usa" }

local schema = {
    type = "object",
    properties = {
        header = {
            description = "header to check.",
            type = "string"
        },
        clusters = {
            type = "array",
            items = {
                type = "object",
                properties = {
                    id = {
                        description = "集群id",
                        type = "string"
                    },
                    tag = {
                        description = "集群标志",
                        type = "string"
                    },
                    desc = {
                        description = "集群描述",
                        type = "string"
                    },
                    host = {
                        description = "集群域名",
                        type = "string"
                    }

                }
            }
        }
    },
    required = {"header", "clusters"},
}

local plugin_name = "test-plugin"

local _M = {
    version = 0.1,
    priority = 12,
    name = plugin_name,
    schema = schema,
}


function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end


local function pair_idc(_route_num, idc_array)
    for _idx, _idc_info in pairs(idc_array) do
        if tonumber(_idc_info.id) == _route_num then
            return _idc_info
        end
    end
end


--

local reg = [[(\\\$[0-9a-zA-Z_]+)|]]         -- \$host
        .. [[\$\{([0-9a-zA-Z_]+)\}|]]    -- ${host}
        .. [[\$([0-9a-zA-Z_]+)|]]        -- $host
        .. [[(\$|[^$\\]+)]]              -- $ or others

local lrucache = core.lrucache.new({
    ttl = 300, count = 100
})

local function parse_uri(uri)
    local iterator, err = re_gmatch(uri, reg, "jiox")
    if not iterator then
        return nil, err
    end

    local t = {}
    while true do
        local m, err = iterator()
        if err then
            return nil, err
        end

        if not m then
            break
        end

        tab_insert(t, m)
    end

    return t
end

local tmp = {}
local function concat_new_uri(uri, ctx)
    local passed_uri_segs, err = lrucache(uri, nil, parse_uri, uri)
    if not passed_uri_segs then
        return nil, err
    end

    core.table.clear(tmp)

    for _, uri_segs in ipairs(passed_uri_segs) do
        local pat1 = uri_segs[1]    -- \$host
        local pat2 = uri_segs[2]    -- ${host}
        local pat3 = uri_segs[3]    -- $host
        local pat4 = uri_segs[4]    -- $ or others
        core.log.info("parsed uri segs: ", core.json.delay_encode(uri_segs))

        if pat2 or pat3 then
            tab_insert(tmp, ctx.var[pat2 or pat3])
        else
            tab_insert(tmp, pat1 or pat4)
        end
    end

    return tab_concat(tmp, "")
end

function _M.rewrite(conf, ctx)
    local token = core.request.header(ctx, conf.header)
    if not token then
        -- uri not login
        return 401, 'not login'
    end
    local _SELF_IDC_NUM = string.sub(token, 1, 1)
    core.log.error("_SELF_IDC_NUM: ", _SELF_IDC_NUM)
    local idc_info = pair_idc(tonumber(_SELF_IDC_NUM), conf.clusters)
    core.log.error("idc_info: ", idc_info.name)

    local uri = idc_info.host

    local err
    new_uri, err = concat_new_uri(uri, ctx)
    if not new_uri then
        core.log.error("failed to generate new uri by: " .. uri .. err)
        return 500
    end

    local new_uri_with_args = new_uri .. ctx.var.uri .. "?" ..  ctx.var.args
    core.log.error("new_uri: ", new_uri_with_args )

    core.response.set_header("Location", new_uri_with_args)
    return 301

end


return _M
