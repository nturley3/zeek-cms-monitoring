##! Module for handling CMS Wordpress data

@load base/protocols/http
@load base/utils/urls
@load base/protocols/http/utils
@load base/frameworks/notice

module CMS;

function wordpress_check_login_complete(c: connection, user_id: string)
{
    # Build the record and write the log
    local log: Info = [
        $ts = network_time(),
        $uid = c$uid,
        $id = c$id
    ];

    if(user_id != "")
    {
        # Set common fields
        log$username = cms_users[user_id]["wordpress"]$username;
        log$pw_length = |cms_users[user_id]["wordpress"]$password|;
        log$cms_uri = cms_users[user_id]["wordpress"]?$cms_uri ? cms_users[user_id]["wordpress"]$cms_uri : "unknown";
        log$cms_app = "wordpress";
        log$lv_dist = cms_users[user_id]["wordpress"]$lv_dist;

        # Set the detected user agent string
        if(cms_users[user_id]["wordpress"]?$user_agent) {
            log$user_agent = cms_users[user_id]["wordpress"]$user_agent;
        }

        # Only expose passwords on specific ports
        if(c$id$resp_p in cleartext_checked_ports) {
            log$password = cms_users[user_id]["wordpress"]$password;
        }
        else
        {
            log$password = "<redacted>";
        }

        if("wordpress" in cms_users[user_id] && /wordpress_logged_in_.*=/ in join_string_set(cms_users[user_id]["wordpress"]$set_cookie, "-")) {
            # Wordpress authentication was successful
            log$cms_success = T;
            Log::write(CMS::LOG, log);
            delete cms_users[user_id];
        } 
        else if("wordpress" in cms_users[user_id] && /wordpress_logged_in_.*=/ !in join_string_set(cms_users[user_id]["wordpress"]$set_cookie, "-")) {
            # Wordpress login failure
            log$cms_success = F;
            Log::write(CMS::LOG, log);
            delete cms_users[user_id];
        }
        else {
            # We're not sure what happened. Return and let document expire. 
            # TODO: Refactor. This may not be needed. 
            return;
        }
    }
}

# WordPress
event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) {
    if(!c$http?$uri)
        return;

    local lp_attrs: table[string] of string;
    local session: SessionContext;
    local user_id: string;
    local cms_uri: set[string];
    local cookies: table[string] of string;

    if(c$http?$post_body) {
        if(/log=/ !in c$http$post_body && /pwd=/ !in c$http$post_body) {
            return;
        }

        lp_attrs = CMS::parse_post_body(c$http$post_body);
        # For Wordpress 5, the log, pwd and wp-submit fields are always seen
        if("log" in lp_attrs && "pwd" in lp_attrs && "wp-submit" in lp_attrs) {
            # print(lp_attrs);
            user_id = lp_attrs["log"];

            session$conn = c$uid;
            session$id = c$id;
            session$username = lp_attrs["log"];
            #if("pwd" !in lp_attrs)
            #{
            #    # Return since login checks won't work if password is missing
            #    Reporter::warning(fmt("User ID %s was missing password in headers. Incomplete CMS WordPress login.", session$username));
            #    return;
            #}
            session$password = lp_attrs["pwd"];
            session$lv_dist = levenshtein_distance(lp_attrs["log"], lp_attrs["pwd"]);

            session$set_cookie = get_set_cookie(hlist);
            cookies = get_cookie_values(session$set_cookie);
            session$cms_uri = HTTP::build_url(c$http);

            if(c$http?$user_agent)
            {
                # Set user agent if available
                session$user_agent = c$http$user_agent;
            }
            cms_users[user_id] = table(
                ["wordpress"] = session
            );
            wordpress_check_login_complete(c, user_id);

            # Redact sensitive information
            c$http$post_body = "<redacted>";
        }
    }
}
